import { sleep } from "../utils.js";
import type { ResponseAction, ResponseContext } from "./types.js";

export interface DripFeedOptions {
  /** Bytes emitted per tick. Default 1. */
  chunkBytes?: number;
  /** Delay between ticks, in ms. Default 1000. */
  intervalMs?: number;
  /** Give up and close after this long. Default 120s. */
  maxDurationMs?: number;
  status?: number;
  /**
   * Max simultaneously-held drip-feeds. Past this, the response ends immediately
   * rather than pinning another socket. Default 256.
   */
  maxConcurrent?: number;
}

/**
 * Answers with a never-quite-finished response, emitting a byte at a time.
 * The connection stays open and the client keeps waiting, so a scanner's
 * worker is pinned for as long as it is willing to wait — the inverse of a
 * slowloris, pointed back at the attacker.
 */
export function dripFeedAction(options: DripFeedOptions = {}): ResponseAction {
  const chunkBytes = options.chunkBytes ?? 1;
  const intervalMs = options.intervalMs ?? 1000;
  const maxDurationMs = options.maxDurationMs ?? 120_000;
  const status = options.status ?? 200;
  const maxConcurrent = options.maxConcurrent ?? 256;
  let active = 0;

  return {
    id: "drip-feed",
    description: "Trickle the response out byte by byte to pin the attacker's connection",
    async execute(ctx: ResponseContext): Promise<void> {
      // A client that reset while evaluation awaited the store has already emitted
      // `close`, so the listener below never fires and the loop would trickle into a
      // dead socket until `maxDurationMs`, holding one of the few slots throughout.
      if (ctx.res.destroyed) return;
      ctx.res.statusCode = status;
      ctx.res.setHeader("Content-Type", "text/html; charset=utf-8");
      // At capacity: send a complete short response instead of pinning another socket.
      if (active >= maxConcurrent) {
        if (!ctx.res.writableEnded) ctx.res.end("<!doctype html><html><body></body></html>");
        return;
      }
      active += 1;
      try {
        const deadline = Date.now() + maxDurationMs;
        let aborted = false;
        ctx.res.on("close", () => (aborted = true));

        // No Content-Length: the client cannot tell how long this will go on.
        ctx.res.write("<!doctype html><html><body>");

        const filler = "<!-- -->".repeat(Math.max(1, Math.ceil(chunkBytes / 8)));
        while (!aborted && !ctx.res.writableEnded && Date.now() < deadline) {
          ctx.res.write(filler.slice(0, chunkBytes));
          await sleep(intervalMs);
        }
        if (!aborted && !ctx.res.writableEnded) ctx.res.end("</body></html>");
      } finally {
        active -= 1;
      }
    },
  };
}
