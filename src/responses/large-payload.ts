import { sleep } from "../utils.js";
import type { ResponseAction, ResponseContext } from "./types.js";

export interface LargePayloadOptions {
  /** Total bytes to stream. Default 50 MB. */
  totalBytes?: number;
  /** Bytes per chunk. Default 64 KB. */
  chunkBytes?: number;
  /** Optional throttle between chunks, in ms, to keep the transfer going a long time. Default 0. */
  throttleMs?: number;
  contentType?: string;
  /**
   * Max simultaneous large-payload streams. Past this, a short response is sent
   * instead, so a flood can't tie up all our upload bandwidth/sockets at once.
   * Default 64.
   */
  maxConcurrent?: number;
}

const FILLER = Buffer.alloc(64 * 1024, 0x41); // 'A' repeated

/**
 * Waits for the socket to drain, but also settles on `close`/`error`.
 *
 * Awaiting a bare `once("drain")` was a slot leak an attacker could trigger on purpose:
 * a client that requests the payload, stops reading (so we go into backpressure), then
 * kills the connection gets `close` — never `drain` — so the promise never settled, the
 * `finally` that releases the concurrency slot never ran, and the async function stayed
 * pinned forever. Repeat `maxConcurrent` times (64 by default) and this response is
 * permanently degraded to an empty body for every future attacker, with the leaked
 * closures retained for the life of the process. Slow-read-then-RST is a standard
 * scanner behaviour, so this fires without the attacker even aiming at it.
 */
function drain(res: ResponseContext["res"]): Promise<void> {
  return new Promise<void>((resolve) => {
    const done = (): void => {
      res.off("drain", done);
      res.off("close", done);
      res.off("error", done);
      resolve();
    };
    res.once("drain", done);
    res.once("close", done);
    res.once("error", done);
  });
}

/**
 * Streams a large, compressible-looking-but-not response to soak up the
 * attacker's bandwidth and storage if they save what they scrape. Generated
 * on the fly from a reused buffer, so it costs us near-zero memory regardless
 * of size. Never sets Content-Encoding, so it will not be transparently
 * gzipped small.
 */
export function largePayloadAction(options: LargePayloadOptions = {}): ResponseAction {
  const totalBytes = Math.max(0, options.totalBytes ?? 50 * 1024 * 1024);
  // At least one byte per chunk, or the stream loop below never advances.
  //
  // `size` is `min(chunkBytes, remaining)`, and `sent += size`. At `chunkBytes = 0`
  // that adds nothing, so `sent < totalBytes` stays true forever — and the loop has no
  // await on that path either: an empty `write()` returns true, so `drain()` is skipped,
  // and `throttleMs` defaults to 0, so `sleep()` is skipped. The result is a tight
  // synchronous spin that pins the event loop for good, taking the HTTP honeypot, the
  // management API and every protocol emulator with it — from the first attacker request
  // routed to this action, with nothing logged. A negative value is worse still: `sent`
  // counts backwards. The config layer now rejects both, but this action is public API a
  // library caller constructs directly, so it holds the floor itself.
  const chunkBytes = Math.max(1, options.chunkBytes ?? 64 * 1024);
  const throttleMs = options.throttleMs ?? 0;
  const contentType = options.contentType ?? "application/octet-stream";
  const maxConcurrent = options.maxConcurrent ?? 64;
  let active = 0;

  return {
    id: "large-payload",
    description: "Stream a large response to waste the attacker's bandwidth and storage",
    async execute(ctx: ResponseContext): Promise<void> {
      // Already gone — the client reset while evaluation awaited the store. `close` has
      // fired, so neither the `aborted` listener nor `drain()` below would ever hear it:
      // the first write on the dead socket reports backpressure and `drain()` waits
      // forever, which is the permanent slot leak `drain()` documents, reached before we
      // subscribe instead of after.
      if (ctx.res.destroyed) return;
      // At capacity: don't start another big stream — send a short body instead.
      if (active >= maxConcurrent) {
        if (!ctx.res.writableEnded) {
          ctx.res.statusCode = 200;
          ctx.res.end();
        }
        return;
      }
      active += 1;
      try {
        let aborted = false;
        ctx.res.on("close", () => (aborted = true));

        ctx.res.statusCode = 200;
        ctx.res.setHeader("Content-Type", contentType);
        ctx.res.setHeader("Content-Length", String(totalBytes));
        ctx.res.setHeader("Content-Disposition", 'attachment; filename="backup.sql"');

        let sent = 0;
        while (sent < totalBytes && !aborted && !ctx.res.writableEnded) {
          const size = Math.min(chunkBytes, totalBytes - sent);
          const chunk = size === FILLER.length ? FILLER : FILLER.subarray(0, size);
          const ok = ctx.res.write(chunk);
          sent += size;
          if (!ok) await drain(ctx.res);
          else if (throttleMs > 0) await sleep(throttleMs);
        }
        if (!aborted && !ctx.res.writableEnded) ctx.res.end();
      } finally {
        active -= 1;
      }
    },
  };
}
