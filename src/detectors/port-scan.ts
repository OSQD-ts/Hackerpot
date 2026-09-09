import net from "node:net";
import { StringDecoder } from "node:string_decoder";

/** Longest probe banner retained per connection. */
const BANNER_CHARS = 512;

export interface PortScanEvent {
  ip: string;
  port: number;
  at: Date;
  /** Distinct sentinel ports this IP has touched so far. */
  portsTouched: number;
  /** True once this IP has touched enough distinct ports to look like a sweep. */
  isScan: boolean;
  /** Bytes the client sent before disconnecting, if any — often a protocol probe banner. */
  banner?: string;
}

export interface PortScanSentinelOptions {
  /** Ports to listen on. Pick ones your real services do not use — any connection here is unsolicited. */
  ports: number[];
  host?: string;
  /** Distinct ports one IP must touch before it is reported as a scan. Default 2. */
  scanThreshold?: number;
  /** Fake service banner to send on connect, e.g. "SSH-2.0-OpenSSH_8.4". Omit to stay silent. */
  banner?: string;
  /**
   * Max source IPs whose touched-port sets are remembered at once. Past this, the
   * least-recently-seen are dropped. Default 10000. These are internet-facing decoy
   * ports that get swept continuously, so this map is the sentinel's only unbounded
   * growth surface — see `remember()`.
   */
  maxTrackedIps?: number;
  /**
   * Reports whether a source IP is allowlisted, so an exempt host is never remembered
   * or reported. See the emulators' `isAllowlisted` for why this is a predicate rather
   * than an `IpAllowlist`: the sentinel is not rebuilt on a SIGHUP reload.
   */
  isAllowlisted?: (ip: string) => boolean;
  /** How long an IP's touched-port set is remembered, in ms. Default 3600000 (1h). */
  retentionMs?: number;
  onEvent?: (event: PortScanEvent) => void | Promise<void>;
}

/**
 * Detects port scanning by listening on ports nothing legitimate should touch.
 * Any inbound connection is unsolicited by definition; an IP reaching several
 * distinct sentinel ports is sweeping the host. This is TCP-level and runs
 * independently of the HTTP engine — attach it to either deployment mode.
 */
export class PortScanSentinel {
  private servers: net.Server[] = [];
  /** Live probe connections, so `close()` can end them instead of waiting on them. */
  private readonly sockets = new Set<net.Socket>();
  private readonly seen = new Map<string, { ports: Set<number>; at: number }>();
  private readonly options: PortScanSentinelOptions;
  private readonly maxTrackedIps: number;
  private readonly retentionMs: number;

  constructor(options: PortScanSentinelOptions) {
    this.options = options;
    this.maxTrackedIps = options.maxTrackedIps ?? 10_000;
    this.retentionMs = options.retentionMs ?? 3_600_000;
  }

  /**
   * Records that `ip` touched `port`, keeping the tracking map bounded.
   *
   * This map previously grew forever: one permanent entry per distinct source address,
   * never expired and never capped. Sentinel ports exist precisely to be connected to
   * by anything on the internet, so the entry count tracks "how many hosts have scanned
   * us since boot" — which for an internet-facing honeypot is unbounded and rises on its
   * own, no attacker effort required. A single host spoofing source addresses drives it
   * far faster. Entries now age out on a retention window and the map is hard-capped,
   * shedding least-recently-seen first.
   */
  private remember(ip: string, port: number, now: number): Set<number> {
    const existing = this.seen.get(ip);
    if (existing) {
      existing.ports.add(port);
      existing.at = now;
      // Re-insert so Map iteration order stays least-recently-seen first.
      this.seen.delete(ip);
      this.seen.set(ip, existing);
      return existing.ports;
    }

    const cutoff = now - this.retentionMs;
    for (const [key, entry] of this.seen) {
      if (entry.at >= cutoff) break; // insertion-ordered: the rest are newer
      this.seen.delete(key);
    }
    while (this.seen.size >= this.maxTrackedIps) {
      const oldest = this.seen.keys().next();
      if (oldest.done) break;
      this.seen.delete(oldest.value);
    }

    const entry = { ports: new Set<number>([port]), at: now };
    this.seen.set(ip, entry);
    return entry.ports;
  }

  async listen(): Promise<void> {
    const threshold = this.options.scanThreshold ?? 2;

    await Promise.all(
      this.options.ports.map(
        (port) =>
          new Promise<void>((resolve, reject) => {
            const server = net.createServer((socket) => {
              const ip = socket.remoteAddress ?? "unknown";
              // Allowlisted sources are exempt from all detection: not remembered, not
              // reported. A TCP health check from an exempt monitor is the ordinary
              // reason a sentinel port sees a connection it should ignore.
              if (this.options.isAllowlisted?.(ip)) {
                socket.destroy();
                return;
              }
              const ports = this.remember(ip, port, Date.now());
              this.sockets.add(socket);
              socket.once("close", () => this.sockets.delete(socket));

              let banner = "";
              // Decode incrementally (a probe banner can be any bytes, and a multi-byte
              // sequence split across segments would decode to replacement characters),
              // and bound what we append rather than only what we later slice: the old
              // check admitted one whole chunk past the limit, so a single 64 KB write
              // was retained in full just to be cut to 512 at close.
              const bannerDecoder = new StringDecoder("utf8");
              socket.setTimeout(5_000, () => socket.destroy());
              socket.on("data", (chunk: Buffer) => {
                if (banner.length >= BANNER_CHARS) return;
                banner = (banner + bannerDecoder.write(chunk)).slice(0, BANNER_CHARS);
              });
              socket.on("error", () => undefined);
              socket.on("close", () => {
                const event: PortScanEvent = {
                  ip,
                  port,
                  at: new Date(),
                  portsTouched: ports.size,
                  isScan: ports.size >= threshold,
                };
                if (banner) event.banner = banner;
                // Isolate a rejecting async onEvent: an attacker sweeping ports must not be
                // able to turn a throwing callback into a process-killing unhandled rejection.
                Promise.resolve(this.options.onEvent?.(event)).catch(() => undefined);
              });

              if (this.options.banner) socket.write(`${this.options.banner}\r\n`);
            });

            // Same ceiling the HTTP listeners get (see http-hardening.ts): these sockets
            // are held for up to the 5s idle timeout, so without a cap a connection flood
            // against a decoy port can exhaust our file descriptors.
            server.maxConnections = 10_000;
            server.once("error", reject);
            server.listen(port, this.options.host, () => {
              server.removeListener("error", reject);
              resolve();
            });
            this.servers.push(server);
          }),
      ),
    );
  }

  /**
   * Stops every sentinel listener and ends any probe connection still open.
   *
   * `server.close()` waits for live connections, and the only per-socket bound here is
   * a 5s *idle* timeout — which every byte resets. A probe writing one byte a second
   * therefore held shutdown open forever, unlike the other emulators, which at least
   * cap a session's total lifetime. Sentinel ports exist to be connected to by hostile
   * traffic, so that is not a rare condition; the sockets are destroyed instead.
   */
  async close(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    await Promise.all(this.servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
    this.servers = [];
  }

  portsTouchedBy(ip: string): number {
    return this.seen.get(ip)?.ports.size ?? 0;
  }

  /** Source IPs currently tracked — bounded by `maxTrackedIps`. */
  get trackedIps(): number {
    return this.seen.size;
  }
}
