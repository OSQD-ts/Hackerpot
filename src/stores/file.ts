import { closeSync, existsSync, mkdirSync, openSync, readFileSync, readSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { RotatingJsonlWriter } from "./archive.js";
import { ScoreLedger } from "./scores.js";
import type { HitStore, HoneypotHit } from "../types.js";

/** Read granularity for the streaming readers. */
const CHUNK_BYTES = 1024 * 1024;
/** Longest single line reassembled before it is abandoned as not-a-record. */
const MAX_LINE_BYTES = 8 * 1024 * 1024;

export interface FileStoreOptions {
  /** Path to the append-only JSON Lines file hits are written to. */
  path: string;
  /** Replay the existing file on startup to rebuild per-IP scores. Default true. */
  loadOnStart?: boolean;
  /**
   * Ceiling on how many bytes of the file a single read pulls into memory. Reads take
   * the **tail** — the most recent hits — and discard a leading partial line. Default
   * 67108864 (64 MB). See `list()` for why this bound has to exist.
   */
  maxReadBytes?: number;
  /** Roll the live file into a compressed archive at this size. 0 disables rotation. Default 134217728 (128 MB). */
  maxBytes?: number;
  /** Compressed archives kept alongside the live file. 0 keeps them all. Default 10. */
  maxArchives?: number;
  /** Delete an archive older than this many ms. 0 disables age pruning. Default 0. */
  maxArchiveAgeMs?: number;
  /** gzip rolled segments. Default true. */
  compressArchives?: boolean;
  /**
   * Cap on per-IP scores held in memory. Least-recently-updated are dropped past this,
   * so an IP under active attack is never the one evicted. Default 100000.
   */
  maxScoreEntries?: number;
  /** Reported write/rotation failures. Recording never throws into the request path. */
  onError?: (error: Error) => void;
}

/**
 * Append-only, dependency-free store that persists every hit as one JSON object
 * per line (JSONL). Per-IP scores are cached in memory for fast lookups and
 * rebuilt from the file on startup, so scores survive a restart. Suitable for a
 * single instance; for multiple instances sharing state, use RedisStore.
 */
export class FileStore implements HitStore {
  private readonly path: string;
  private readonly maxReadBytes: number;
  private readonly writer: RotatingJsonlWriter;
  private readonly scores: ScoreLedger;
  private readonly checkpointPath: string;
  /**
   * Queued-but-not-yet-written hits, FIFO, mirroring the writer's own buffer. Scores
   * move into the ledger only when the writer reports the line durable, so at rotation
   * the ledger is exactly "what the archives hold" — see `writeCheckpoint`.
   */
  private readonly inFlight: Array<{ ip: string; score: number }> = [];
  private readonly onError: ((error: Error) => void) | undefined;
  /** True once a read had to drop older records to stay under `maxReadBytes`. */
  truncated = false;

  constructor(options: FileStoreOptions) {
    this.path = options.path;
    this.maxReadBytes = Math.max(1024, options.maxReadBytes ?? 64 * 1024 * 1024);
    this.scores = new ScoreLedger(options.maxScoreEntries ?? 100_000);
    this.onError = options.onError;
    mkdirSync(dirname(this.path), { recursive: true });
    this.checkpointPath = `${this.path}.scores.json`;
    if (options.loadOnStart ?? true) this.replay();
    const writerOptions: ConstructorParameters<typeof RotatingJsonlWriter>[0] = {
      path: this.path,
      onRotate: () => this.writeCheckpoint(),
      onDurable: (count) => this.commitScores(count),
      onDrop: (count) => this.inFlight.splice(0, count),
      maxBytes: options.maxBytes ?? 128 * 1024 * 1024,
      maxArchives: options.maxArchives ?? 10,
      maxAgeMs: options.maxArchiveAgeMs ?? 0,
      compress: options.compressArchives ?? true,
    };
    if (options.onError) writerOptions.onError = options.onError;
    this.writer = new RotatingJsonlWriter(writerOptions);
  }

  /** Compressed archives rolled off the live file, newest first. */
  archives(): string[] {
    return this.writer.archives();
  }

  /** Records discarded because the write buffer was saturated. See `RotatingJsonlWriter.append`. */
  get dropped(): number {
    return this.writer.dropped;
  }

  /** Flushes buffered writes and releases the file handle. */
  async close(): Promise<void> {
    await this.writer.close();
  }

  /**
   * Streams the file from `fromByte`, handing each complete line to `onLine`.
   *
   * Nothing here ever holds more than one chunk plus one line, which is the whole
   * point: both read paths used `readFileSync` on a file that is append-only, never
   * rotated, and grown by the attacker — one JSON record per malicious request, headers
   * and up to 64 KB of body included. So the file's size is a remote input, and loading
   * it whole was a remote OOM on two separate paths:
   *
   *  - `list()`, which every management endpoint sits on (`/incidents`, `/stats`,
   *    `/metrics`, `/ioc`, `/sessions`, `/actors`) and which Prometheus typically
   *    scrapes every 15s — so the operator's view of an attack dies exactly when they
   *    need it, and takes the honeypot process with it, since the store shares it.
   *  - `replay()` at construction, which is worse: the process then cannot start at
   *    all. An attacker inflates the file, the next restart (a deploy, a crash, the OOM
   *    above) fails, and retries keep failing — the honeypot is off until someone
   *    manually truncates the file.
   *
   * Streaming fixes both without giving anything up: `replay()` still sees every record,
   * so per-IP scores stay complete and blocking decisions are unchanged.
   */
  private eachLine(fromByte: number, onLine: (line: string) => void): void {
    const fd = openSync(this.path, "r");
    try {
      const chunk = Buffer.allocUnsafe(CHUNK_BYTES);
      let position = fromByte;
      let carry = "";
      for (;;) {
        const read = readSync(fd, chunk, 0, CHUNK_BYTES, position);
        if (read <= 0) break;
        position += read;
        const text = carry + chunk.subarray(0, read).toString("utf8");
        const lines = text.split("\n");
        // The last element is a partial line (or "" when the chunk ended on a newline).
        carry = lines.pop() ?? "";
        // A file with no newlines at all — foreign content, or a single colossal record
        // — must not turn the carry into the unbounded buffer we just removed.
        if (carry.length > MAX_LINE_BYTES) carry = "";
        for (const line of lines) onLine(line);
      }
      if (carry) onLine(carry);
    } finally {
      closeSync(fd);
    }
  }

  /**
   * Rebuilds per-IP scores: the checkpoint of everything already rotated away, plus
   * every record still in the live segment.
   *
   * Rotation would otherwise have quietly broken what `load_on_start` promises. Replay
   * reads the live segment, and rotation is what empties it — so after the first roll an
   * attacker's accrued suspicion silently reset to whatever the current segment held.
   * That is a security regression, not just lost history: cumulative score is what
   * crosses the block threshold, so a long-running attacker would be handed a clean
   * slate by an unrelated restart.
   *
   * The checkpoint closes it. It is written at each roll, at the one moment the live
   * segment is empty, so "checkpoint + live segment" is exactly the full history with
   * nothing counted twice. It is also small and bounded (one number per tracked IP,
   * capped by `maxScoreEntries`), which is why this stays a fast synchronous read
   * instead of decompressing gigabytes of archives at boot.
   */
  private replay(): void {
    try {
      if (existsSync(this.checkpointPath)) {
        const saved = JSON.parse(readFileSync(this.checkpointPath, "utf8")) as Record<string, number>;
        this.scores.seed(saved);
      }
    } catch (err) {
      // A damaged checkpoint costs history, not startup.
      this.onError?.(err instanceof Error ? err : new Error(String(err)));
    }
    if (!existsSync(this.path)) return;
    this.eachLine(0, (line) => {
      if (!line.trim()) return;
      try {
        const hit = JSON.parse(line) as HoneypotHit;
        this.scores.add(hit.ip, hit.score);
      } catch {
        // Skip a corrupt/partial line rather than failing startup.
      }
    });
  }

  /**
   * Persists the score ledger. Called only at rotation, while the live segment is
   * empty — see `replay()` for why that timing is what keeps the sum exact. Written to
   * a temp file and renamed so a crash mid-write can never leave a half-parsed
   * checkpoint behind.
   */
  private writeCheckpoint(): void {
    try {
      const temp = `${this.checkpointPath}.tmp`;
      writeFileSync(temp, JSON.stringify(this.scores.entries()));
      renameSync(temp, this.checkpointPath);
    } catch (err) {
      // Never let a checkpoint failure stop the honeypot recording hits.
      this.onError?.(err instanceof Error ? err : new Error(String(err)));
    }
  }

  /**
   * Appends the hit, asynchronously and batched — never `appendFileSync`.
   *
   * The returned promise settles once the line is written, so `await record(); list()`
   * still sees it and ordering is unchanged. What changed is that the write no longer
   * halts the event loop: a synchronous append froze every other in-flight request for
   * the duration of the disk write, at a frequency the attacker chose. See
   * `RotatingJsonlWriter` for that and for how the file is kept from filling the disk.
   */
  record(hit: HoneypotHit): Promise<void> {
    this.inFlight.push({ ip: hit.ip, score: hit.score });
    return this.writer.append(JSON.stringify(hit));
  }

  /** Moves the oldest `count` queued hits into the ledger, now that they are on disk. */
  private commitScores(count: number): void {
    for (const entry of this.inFlight.splice(0, count)) this.scores.add(entry.ip, entry.score);
  }

  /**
   * The most recent hits in the file, skipping any line that won't parse.
   *
   * `replay()` already tolerated a corrupt line; this did not, and it is the read path
   * the whole management API sits on (`/incidents`, `/stats`, `/metrics`, `/ioc`,
   * `/sessions`, `/actors` all call it). One truncated line — a crash mid-append, a
   * full disk, two instances sharing a path — turned every one of those endpoints into
   * a permanent 500, so the operator loses visibility into an ongoing attack at exactly
   * the moment they need it. A malformed line is a damaged record, not a reason to stop
   * serving the intact ones.
   *
   * Bounded to the newest `maxReadBytes` of the file and streamed a chunk at a time —
   * see `eachLine()`. When the file is larger than that, older records are not returned
   * and `truncated` is set.
   */
  list(): HoneypotHit[] {
    if (!existsSync(this.path)) return [];
    const size = statSync(this.path).size;
    // Read only the newest `maxReadBytes`. The recent window is what an operator
    // responding to a live attack is reading anyway, and it is what keeps every
    // management endpoint answering however large the file has grown.
    const from = Math.max(0, size - this.maxReadBytes);
    if (from > 0) this.truncated = true;

    const hits: HoneypotHit[] = [];
    let first = true;
    this.eachLine(from, (line) => {
      // A non-zero offset almost certainly lands mid-record; drop that partial line
      // rather than handing a half-record to JSON.parse.
      if (first) {
        first = false;
        if (from > 0) return;
      }
      if (!line.trim()) return;
      try {
        hits.push(JSON.parse(line) as HoneypotHit);
      } catch {
        // Skip a corrupt/partial line rather than failing every read.
      }
    });
    return hits;
  }

  scoreFor(ip: string): number {
    return this.scores.get(ip);
  }
}
