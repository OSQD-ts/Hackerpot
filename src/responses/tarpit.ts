import { resolveDelay } from "../utils.js";
import type { ResponseAction, ResponseContext } from "./types.js";

export interface TarpitOptions {
  /** Delay before responding, in ms. A [min, max] tuple randomizes it. Default [2000, 8000]. */
  delayMs?: number | [number, number];
  status?: number;
  body?: string;
  /** Scale the delay with the IP's cumulative suspicion score, up to 4x. Default true. */
  escalate?: boolean;
  /**
   * Max simultaneously-held tarpits. Past this, requests are answered immediately
   * instead of held, so a flood can't pin more of our own sockets than we allow.
   * Default 1000.
   */
  maxConcurrent?: number;
}

/**
 * Holds the request open before answering, to burn the attacker's wall-clock
 * time and occupy a slot in their scanner's connection pool. Cheap for us
 * (an idle timer), expensive for them at scale — but capped, so the attacker
 * can't invert it and exhaust *our* sockets.
 */
export function tarpitAction(options: TarpitOptions = {}): ResponseAction {
  const base = options.delayMs ?? ([2000, 8000] as [number, number]);
  const status = options.status ?? 404;
  const body = options.body ?? "Not Found";
  const escalate = options.escalate ?? true;
  const maxConcurrent = options.maxConcurrent ?? 1000;
  let active = 0;

  const respond = (ctx: ResponseContext): void => {
    if (ctx.res.writableEnded) return;
    ctx.res.statusCode = status;
    ctx.res.setHeader("Content-Type", "text/plain; charset=utf-8");
    ctx.res.end(body);
  };

  return {
    id: "tarpit",
    description: "Delay the response to waste the attacker's time",
    async execute(ctx: ResponseContext): Promise<void> {
      // Already gone: the `close` listener below would never fire, because the event
      // fired while evaluation was still awaiting the store (a Redis round-trip is
      // plenty), and the slot would sit out the full delay on a socket that no longer
      // exists. Request-then-reset refills slots faster than they drain — the same
      // switch-off described below, reached before we ever subscribe.
      if (ctx.res.destroyed) return;
      // At capacity: answer immediately rather than holding another socket.
      if (active >= maxConcurrent) {
        respond(ctx);
        return;
      }
      active += 1;
      try {
        let delay = resolveDelay(base);
        if (escalate) delay *= Math.min(4, 1 + ctx.totalScore / 50);

        // Wait for the delay OR the client giving up, whichever comes first — never
        // just the delay. A bare `sleep()` kept the slot held for the full (escalated,
        // up to 4x) delay even after the attacker hung up, so a client that connects
        // and immediately RSTs costs us a slot for up to ~32s while costing them
        // nothing. Repeat that faster than the slots drain and `active` sits at
        // `maxConcurrent` permanently, at which point every real probe takes the
        // at-capacity branch and is answered instantly: the tarpit is switched off by
        // the very traffic it exists to punish. Connect-and-drop is what a scanner does
        // when it times out, so this needs no deliberate targeting. The timer is
        // cleared on disconnect rather than left to fire into a dead response.
        const abandoned = await new Promise<boolean>((resolve) => {
          let onClose: () => void;
          const timer = setTimeout(() => {
            ctx.res.off("close", onClose);
            resolve(false);
          }, Math.round(delay));
          onClose = () => {
            clearTimeout(timer);
            resolve(true);
          };
          ctx.res.once("close", onClose);
        });
        if (abandoned) return;
        respond(ctx);
      } finally {
        active -= 1;
      }
    },
  };
}
