import { createReadStream, createWriteStream, existsSync, mkdirSync, readdirSync, renameSync, statSync, unlinkSync } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { pipeline } from "node:stream/promises";
import { createGzip } from "node:zlib";

export interface RotatingJsonlWriterOptions {
  /** Path of the live segment. Archived segments are siblings of it. */
  path: string;
  /** Roll the live segment once it reaches this many bytes. 0 disables rotation. Default 134217728 (128 MB). */
  maxBytes?: number;
  /** Archived segments kept. Oldest are deleted past this. 0 keeps them all. Default 10. */
  maxArchives?: number;
  /** Delete an archived segment once it is older than this many ms. 0 disables age pruning. Default 0. */
  maxAgeMs?: number;
  /** gzip archived segments. Default true. */
  compress?: boolean;
  /**
   * Hard ceiling on lines buffered in memory awaiting a write. Past this, lines are
   * dropped and counted in `dropped` — see `append()`. Default 50000.
   */
  maxPendingLines?: number;
  /**
   * Called synchronously with the number of lines that just became durable, in FIFO
   * order, *before* any rotation check. Lets a caller keep derived state (the score
   * ledger) tied to what is actually on disk rather than what has merely been queued —
   * which is what makes the rotation checkpoint exact.
   */
  onDurable?: (count: number) => void;
  /** Called with the number of lines discarded from the head of a saturated buffer. */
  onDrop?: (count: number) => void;
  /**
   * Called right after a successful roll, while the live segment is empty. That empty
   * window is what makes a checkpoint of derived state (see `FileStore`'s score
   * sidecar) unambiguous: everything the checkpoint covers has left the live segment,
   * so replaying the segment on top of it can never double-count.
   */
  onRotate?: () => void | Promise<void>;
  /** Reported rotation/compression/pruning failures. Writing continues regardless. */
  onError?: (error: Error) => void;
}

interface Waiter {
  resolve: () => void;
  reject: (error: Error) => void;
}

const ARCHIVE_PATTERN = /-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z(-\d+)?\.jsonl(\.gz)?$/;

/**
 * Append-only JSONL writer that never blocks the event loop and never fills the disk.
 *
 * It replaces a bare `appendFileSync` per hit, which was two problems at once on the
 * request path of an internet-facing service:
 *
 *  - **Synchronous disk I/O per hit.** `appendFileSync` stops the entire event loop —
 *    every other in-flight request, every timer, every socket — until the write
 *    returns. Under an attack the write rate *is* the attack rate, and on a slow or
 *    contended disk (a network volume, a noisy neighbour, an fsync storm) each hit
 *    costs milliseconds of total stall. The attacker sets the frequency, so this is a
 *    remote throttle on the whole process, and in middleware mode on the host app too.
 *  - **Unbounded growth.** The file was append-only with no rotation, one record per
 *    malicious request including headers and up to 64 KB of body, so a sustained
 *    attack simply filled the volume — and taking the disk to 100% takes down far more
 *    than the honeypot.
 *
 * So writes are batched and asynchronous (concurrent hits coalesce into one `write`),
 * and the live segment rolls into a compressed archive at `maxBytes` with old archives
 * pruned. `append()` still returns a promise that settles when the line is durable, so
 * a caller that awaits it keeps read-after-write ordering exactly as before.
 */
export class RotatingJsonlWriter {
  readonly path: string;
  private readonly maxBytes: number;
  private readonly maxArchives: number;
  private readonly maxAgeMs: number;
  private readonly compress: boolean;
  private readonly maxPendingLines: number;
  private readonly onError: ((error: Error) => void) | undefined;
  private readonly onRotate: (() => void | Promise<void>) | undefined;
  private readonly onDurable: ((count: number) => void) | undefined;
  private readonly onDrop: ((count: number) => void) | undefined;

  private handle: FileHandle | undefined;
  private liveBytes = 0;
  private pending: string[] = [];
  private waiters: Waiter[] = [];
  private running: Promise<void> | undefined;
  private closed = false;
  /** Lines discarded because the in-memory buffer hit `maxPendingLines`. */
  dropped = 0;

  constructor(options: RotatingJsonlWriterOptions) {
    this.path = options.path;
    this.maxBytes = Math.max(0, options.maxBytes ?? 128 * 1024 * 1024);
    this.maxArchives = Math.max(0, options.maxArchives ?? 10);
    this.maxAgeMs = Math.max(0, options.maxAgeMs ?? 0);
    this.compress = options.compress ?? true;
    this.maxPendingLines = Math.max(1, options.maxPendingLines ?? 50_000);
    this.onError = options.onError;
    this.onRotate = options.onRotate;
    this.onDurable = options.onDurable;
    this.onDrop = options.onDrop;
    mkdirSync(dirname(this.path), { recursive: true });
    this.liveBytes = existsSync(this.path) ? statSync(this.path).size : 0;
  }

  /**
   * Queues one line (a newline is added) and resolves once it has been written.
   *
   * The buffer is capped. An async queue in front of a slow disk is itself an
   * unbounded memory sink — exactly the failure we removed from the disk, relocated
   * into the heap — so past `maxPendingLines` the oldest queued line is dropped and
   * counted. Losing the oldest few records under a write-saturating flood is a far
   * better outcome than an OOM that loses the process and every record with it.
   */
  append(line: string): Promise<void> {
    if (this.closed) return Promise.reject(new Error("writer is closed"));
    if (this.pending.length >= this.maxPendingLines) {
      this.pending.shift();
      this.waiters.shift()?.resolve();
      this.dropped += 1;
      this.onDrop?.(1);
    }
    this.pending.push(line);
    const settled = new Promise<void>((resolve, reject) => this.waiters.push({ resolve, reject }));
    this.schedule();
    return settled;
  }

  /** Resolves once everything queued so far has been written. */
  async flush(): Promise<void> {
    this.schedule();
    await this.running;
  }

  /** Flushes, then releases the file handle. Further `append()` calls reject. */
  async close(): Promise<void> {
    this.closed = true;
    await this.running;
    await this.handle?.close();
    this.handle = undefined;
  }

  /** Archived segment paths, newest first. Not read by the store — for operators and tooling. */
  archives(): string[] {
    const dir = dirname(this.path);
    const stem = basename(this.path).replace(/\.jsonl$/, "");
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
      .filter((name) => name.startsWith(`${stem}-`) && ARCHIVE_PATTERN.test(name))
      .sort()
      .reverse()
      .map((name) => join(dir, name));
  }

  private schedule(): void {
    if (this.running) return;
    this.running = this.drain().finally(() => {
      this.running = undefined;
      // Anything queued while we were writing gets its own pass.
      if (this.pending.length > 0 && !this.closed) this.schedule();
    });
  }

  private async drain(): Promise<void> {
    while (this.pending.length > 0) {
      const lines = this.pending;
      const waiters = this.waiters;
      this.pending = [];
      this.waiters = [];
      const payload = `${lines.join("\n")}\n`;
      try {
        const handle = await this.openLive();
        await handle.write(payload);
        this.liveBytes += Buffer.byteLength(payload);
        // Durable first, then wake the callers: an `await append()` must observe any
        // derived state the caller keys off this batch as already updated.
        this.onDurable?.(lines.length);
        for (const waiter of waiters) waiter.resolve();
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        for (const waiter of waiters) waiter.reject(error);
        this.onError?.(error);
        return;
      }
      if (this.maxBytes > 0 && this.liveBytes >= this.maxBytes) await this.rotate();
    }
  }

  private async openLive(): Promise<FileHandle> {
    if (!this.handle) this.handle = await open(this.path, "a");
    return this.handle;
  }

  /**
   * Rolls the live segment out of the way and starts a fresh one.
   *
   * Rotation runs inside the write chain, so no append can land while the file is
   * being renamed. Compression and pruning are best-effort: a failure there must not
   * stop the honeypot recording hits, so it is reported and the writer carries on with
   * a fresh live segment either way.
   */
  private async rotate(): Promise<void> {
    try {
      await this.handle?.close();
      this.handle = undefined;
      const rolled = this.nextArchivePath();
      renameSync(this.path, rolled);
      this.liveBytes = 0;
      // Recreate the live segment immediately so the path an operator is tailing (and
      // the store's own reads) never briefly vanishes between a roll and the next hit.
      this.handle = await open(this.path, "a");
      // Checkpoint derived state while the live segment is empty — see `onRotate`.
      await this.onRotate?.();
      if (this.compress) await this.gzip(rolled);
      this.prune();
    } catch (err) {
      this.onError?.(err instanceof Error ? err : new Error(String(err)));
      this.liveBytes = 0;
    }
  }

  /**
   * An archive path that is not already taken.
   *
   * The name is the roll time, and `toISOString()` resolves to milliseconds — so two
   * rolls inside the same millisecond produced the *same* name, and `renameSync`
   * overwrote the earlier archive without a word. That is silent destruction of
   * captured evidence, and the rate is set by the attacker: rotation frequency follows
   * write volume, which follows the attack. Measured on the shipped defaults, a
   * straight run of 100 records through a 1 KB segment lost records on 12 of 12
   * attempts — 462 records in total, whole segments at a time. The suite caught it only
   * intermittently because it depends on how fast the writes happen to land.
   *
   * A discriminator is appended until the name is free. Both extensions are checked:
   * after `gzip()` the plain `.jsonl` is unlinked and only `.jsonl.gz` remains, so
   * testing for the uncompressed name alone would step straight onto the compressed
   * one. Ordering across different milliseconds is unaffected — the suffix only ever
   * follows a complete timestamp.
   */
  private nextArchivePath(): string {
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const base = this.path.replace(/(\.jsonl)?$/, `-${stamp}`);
    const taken = (candidate: string): boolean => existsSync(candidate) || existsSync(`${candidate}.gz`);

    let candidate = `${base}.jsonl`;
    for (let n = 1; taken(candidate); n += 1) candidate = `${base}-${n}.jsonl`;
    return candidate;
  }

  private async gzip(source: string): Promise<void> {
    const target = `${source}.gz`;
    await pipeline(createReadStream(source), createGzip(), createWriteStream(target));
    unlinkSync(source);
  }

  /** Enforces `maxArchives` and `maxAgeMs`, oldest first. */
  private prune(): void {
    let archives = this.archives(); // newest first
    if (this.maxAgeMs > 0) {
      const cutoff = Date.now() - this.maxAgeMs;
      archives = archives.filter((file) => {
        if (statSync(file).mtimeMs >= cutoff) return true;
        unlinkSync(file);
        return false;
      });
    }
    if (this.maxArchives > 0) {
      for (const file of archives.slice(this.maxArchives)) unlinkSync(file);
    }
  }
}
