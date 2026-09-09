import dgram from "node:dgram";
import net from "node:net";
import type { HoneypotHit } from "./types.js";
import { syslogLine } from "./formats.js";
import { formatTextLine } from "./logfmt.js";

/**
 * Ships incidents to a syslog collector — the sink every SIEM already has an input
 * for, and the one that needs no HTTP endpoint standing up to receive it.
 *
 * Deliberately NOT part of the management API. Webhooks live there because they are
 * an operator-facing feature of an operator-facing service, but syslog forwarding is
 * plumbing: a deployment should be able to ship to its SIEM without also exposing a
 * REST API over its captured attacker data. So this attaches to whatever feeds it —
 * an `IncidentBroker`, or the standalone service's hit path directly.
 *
 * Three rules the transport holds, all for the same reason — this is fed by attacker
 * traffic, at a rate the attacker chooses:
 *
 * 1. **One message per line, always.** Syslog is line-framed. A newline inside a
 *    captured value would end our record and let whatever follows be read as a
 *    separate event, with a source IP of the attacker's choosing, indistinguishable
 *    from a real detection. The formatters escape; this strips again anyway.
 * 2. **Bounded messages.** RFC 3164 only obliges a receiver to accept 1024 bytes, and
 *    a UDP datagram beyond the path MTU is silently lost — so a captured payload is
 *    truncated rather than allowed to turn into a message nobody receives.
 * 3. **Drop, never queue.** When the TCP collector is down, messages are discarded and
 *    the loss is reported. A queue in front of an unavailable consumer is just
 *    unbounded memory growth moved somewhere less visible — the same call the webhook
 *    dispatcher and the firewall enforcer make.
 */

/** Which rendering goes inside the syslog envelope. */
export type SyslogMessageFormat = "cef" | "json" | "text";

export interface SyslogSinkOptions {
  /** Collector address. */
  host: string;
  /** Collector port. Default 514. */
  port?: number;
  /** Transport. UDP is fire-and-forget; TCP reconnects and reports what it drops. Default "udp". */
  protocol?: "udp" | "tcp";
  /** How the message inside the envelope is rendered. Default "cef" — what a SIEM parses natively. */
  format?: SyslogMessageFormat;
  /** Syslog facility (0-23). Default 13 (log audit). */
  facility?: number;
  /** Syslog severity (0-7). Default 4 (warning). */
  severity?: number;
  /** Hostname written into the syslog header. Default "hackerpot". */
  hostname?: string;
  /** Only forward incidents whose total score is at least this. Default 0 (everything). */
  minScore?: number;
  /** Ceiling on one rendered message, in bytes. Default 1024 (the RFC 3164 floor). */
  maxBytes?: number;
  /**
   * TCP only: most bytes allowed to sit unflushed in the socket before messages are
   * dropped instead of written. Default 1048576 (1 MB).
   *
   * "Drop, never queue" covered a collector that was *down* — no socket, so nothing to
   * queue into. It did not cover the collector that is connected and simply not reading,
   * which is the more common failure (a wedged SIEM ingester, a stalled TLS terminator,
   * a full receive window). `socket.write()` returns false there and Node buffers the
   * message in `writableBuffer` regardless, so the queue we refused to keep was being
   * kept for us, in the same process, growing at the rate the attacker chooses. This is
   * the same bound applied where it actually binds.
   */
  maxQueuedBytes?: number;
  /** Include the attacker-controlled request body in the message. Default false. */
  includeBody?: boolean;
  /** Surfaces a transport failure. Never throws into the caller regardless. */
  onError?: (error: Error) => void;
}

const DEFAULT_PORT = 514;
const DEFAULT_MAX_BYTES = 1024;
const DEFAULT_MAX_QUEUED_BYTES = 1024 * 1024;
const RECONNECT_BASE_MS = 500;
const RECONNECT_MAX_MS = 30_000;

/**
 * Truncates to a byte budget without splitting a UTF-8 character.
 *
 * Cutting mid-sequence would emit a lone continuation byte, which is what turns a
 * captured non-ASCII payload into mojibake in the SIEM — or, on a strict parser,
 * into a rejected record.
 */
export function truncateBytes(text: string, maxBytes: number): string {
  const buf = Buffer.from(text, "utf8");
  if (buf.length <= maxBytes) return text;
  let end = maxBytes;
  while (end > 0 && (buf[end]! & 0xc0) === 0x80) end -= 1;
  return buf.subarray(0, end).toString("utf8");
}

/** Final framing guard: whatever the formatters did, one message is one line. */
function oneLine(text: string): string {
  return text.replace(/[\r\n]+/g, " ");
}

export class SyslogSink {
  private readonly opts: SyslogSinkOptions;
  private readonly port: number;
  private readonly protocol: "udp" | "tcp";
  private readonly format: SyslogMessageFormat;
  private readonly minScore: number;
  private readonly maxBytes: number;
  private readonly includeBody: boolean;
  private readonly maxQueuedBytes: number;

  private udp: dgram.Socket | undefined;
  private tcp: net.Socket | undefined;
  private tcpReady = false;
  private reconnectTimer: NodeJS.Timeout | undefined;
  private reconnectAttempt = 0;
  private closed = false;
  private unsubscribe: (() => void) | undefined;

  /** Messages discarded because the TCP collector was unavailable. */
  private dropped = 0;
  /** So a flood reports the outage once, not once per lost message. */
  private outageReported = false;

  constructor(options: SyslogSinkOptions) {
    this.opts = options;
    this.port = options.port ?? DEFAULT_PORT;
    this.protocol = options.protocol ?? "udp";
    this.format = options.format ?? "cef";
    this.minScore = options.minScore ?? 0;
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
    this.includeBody = options.includeBody ?? false;
    this.maxQueuedBytes = Math.max(0, options.maxQueuedBytes ?? DEFAULT_MAX_QUEUED_BYTES);
  }

  /**
   * Opens the transport ahead of the first incident.
   *
   * Optional but worth calling at startup for TCP: the connection is otherwise opened
   * by the first `send()`, which is then dropped for want of a ready socket — so the
   * first thing an attacker does is the one event that never reaches the SIEM. Calling
   * this also surfaces an unreachable collector at startup rather than mid-attack.
   * A no-op for UDP, which has nothing to establish.
   */
  start(): void {
    if (this.closed || this.protocol !== "tcp") return;
    this.connectTcp();
  }

  /** Subscribe to a broker. Returns nothing; use `detach()` to stop. */
  attach(broker: { subscribe: (listener: (incident: HoneypotHit) => void) => () => void }): void {
    this.unsubscribe = broker.subscribe((incident) => this.send(incident));
  }

  detach(): void {
    this.unsubscribe?.();
    this.unsubscribe = undefined;
  }

  /**
   * Ships one incident. Never throws and never returns a promise: it sits directly on
   * the hit path, where a rejection would become an unhandled rejection an attacker
   * triggers at will just by probing.
   */
  send(hit: HoneypotHit): void {
    if (this.closed) return;
    if (hit.totalScore < this.minScore) return;
    try {
      const line = truncateBytes(oneLine(this.render(hit)), this.maxBytes);
      if (this.protocol === "udp") this.sendUdp(line);
      else this.sendTcp(line);
    } catch (err) {
      this.opts.onError?.(err as Error);
    }
  }

  /** Releases the transport. Safe to call when nothing was ever opened. */
  async close(): Promise<void> {
    this.closed = true;
    this.detach();
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.tcp?.destroy();
    this.tcp = undefined;
    this.tcpReady = false;
    const udp = this.udp;
    this.udp = undefined;
    if (!udp) return;
    await new Promise<void>((resolve) => udp.close(() => resolve()));
  }

  /** Messages lost so far because the collector was unreachable. */
  get droppedCount(): number {
    return this.dropped;
  }

  private render(hit: HoneypotHit): string {
    const options: Parameters<typeof syslogLine>[1] = {};
    if (this.opts.hostname !== undefined) options.host = this.opts.hostname;
    if (this.opts.facility !== undefined) options.facility = this.opts.facility;
    if (this.opts.severity !== undefined) options.severity = this.opts.severity;

    if (this.format === "cef") {
      // syslogLine defaults its message to the CEF line, which already escapes the
      // attacker-controlled fields for a line-oriented format.
      return syslogLine(hit, options);
    }
    const event = this.event(hit);
    options.message = this.format === "json" ? JSON.stringify(event) : formatTextLine(event);
    return syslogLine(hit, options);
  }

  /** The field set the json/text renderings carry — the same shape the standalone log emits. */
  private event(hit: HoneypotHit): Record<string, unknown> {
    const event: Record<string, unknown> = {
      ts: hit.timestamp,
      kind: "hit",
      id: hit.id,
      ip: hit.ip,
      method: hit.method,
      path: hit.path,
      score: hit.score,
      totalScore: hit.totalScore,
      respondedWith: hit.respondedWith,
      detectors: hit.detections.map((d) => d.detectorId).join(","),
    };
    if (this.includeBody && hit.body !== undefined) event["body"] = hit.body;
    return event;
  }

  private sendUdp(line: string): void {
    if (!this.udp) {
      // An IPv6 literal needs a udp6 socket; a hostname resolves either way through
      // udp4's dual-stack lookup, which is the common case.
      this.udp = dgram.createSocket(net.isIPv6(this.opts.host) ? "udp6" : "udp4");
      this.udp.on("error", (err) => this.opts.onError?.(err));
      // Never let a fire-and-forget socket hold the process open at shutdown.
      this.udp.unref();
    }
    const payload = Buffer.from(line, "utf8");
    this.udp.send(payload, 0, payload.length, this.port, this.opts.host, (err) => {
      if (err) this.opts.onError?.(err);
    });
  }

  private sendTcp(line: string): void {
    if (!this.tcp) this.connectTcp();
    if (!this.tcpReady || !this.tcp) {
      this.reportDrop(`syslog ${this.opts.host}:${this.port} unavailable — messages are being dropped, not queued`);
      return;
    }
    // A connected-but-not-reading collector is still a consumer we must not queue for:
    // past the ceiling the message goes on the floor, exactly as it would if the
    // collector were down. See `maxQueuedBytes`.
    if (this.tcp.writableLength > this.maxQueuedBytes) {
      this.reportDrop(
        `syslog ${this.opts.host}:${this.port} is not draining — ${this.tcp.writableLength} bytes unflushed, messages are being dropped, not queued`,
      );
      return;
    }
    this.tcp.write(`${line}\n`);
  }

  /** Counts one dropped message, reporting the outage once rather than once per loss. */
  private reportDrop(message: string): void {
    this.dropped += 1;
    if (this.outageReported) return;
    this.outageReported = true;
    this.opts.onError?.(new Error(message));
  }

  private connectTcp(): void {
    if (this.closed || this.tcp) return;
    const socket = net.connect({ host: this.opts.host, port: this.port });
    this.tcp = socket;
    // Attach before anything else can emit: an 'error' with no listener is rethrown
    // as an uncaughtException, and a refused connection to a collector that is simply
    // down would then take the honeypot with it.
    socket.on("error", (err) => {
      this.opts.onError?.(err);
      this.teardownTcp();
    });
    socket.on("close", () => this.teardownTcp());
    socket.on("connect", () => {
      this.tcpReady = true;
      this.reconnectAttempt = 0;
      if (this.dropped > 0 && this.outageReported) {
        this.opts.onError?.(new Error(`syslog ${this.opts.host}:${this.port} reconnected — ${this.dropped} message(s) were dropped while it was down`));
      }
      this.outageReported = false;
    });
    // The collector connection must never be the reason the process stays alive.
    socket.unref();
  }

  private teardownTcp(): void {
    this.tcp?.destroy();
    this.tcp = undefined;
    this.tcpReady = false;
    if (this.closed || this.reconnectTimer) return;
    // Exponential backoff, capped: a collector that is down for an hour must not be
    // dialled thousands of times, and the honeypot must not care that it is down.
    const delay = Math.min(RECONNECT_BASE_MS * 2 ** this.reconnectAttempt, RECONNECT_MAX_MS);
    this.reconnectAttempt += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connectTcp();
    }, delay);
    this.reconnectTimer.unref?.();
  }
}
