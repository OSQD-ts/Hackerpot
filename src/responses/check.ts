import http from "node:http";
import type { AddressInfo } from "node:net";
import { MemoryBlocklist } from "../blocklist.js";
import type { Detection } from "../detectors/types.js";
import { IpTracker } from "../state.js";
import type { ResponseAction, ResponseContext } from "./types.js";

export interface ResponseCheckResult {
  id: string;
  /**
   * `ok`: the response completed. `held`: still delaying or streaming when the budget ran
   * out, which is the job of `tarpit`, `drip-feed` and `large-payload`. `failed`: the
   * action threw, rejected, or reported an error through `onError`.
   *
   * A 5xx on its own is not a failure: `chaos` answers one on purpose.
   */
  outcome: "ok" | "held" | "failed";
  /** The status the client received, when a response arrived before the budget. */
  status?: number;
  error?: string;
}

export interface CheckResponseActionsOptions {
  /** How long to wait for each action's response before calling it `held`. Default 1500. */
  budgetMs?: number;
}

/** TEST-NET-1, reserved for documentation: never a real client. */
const CHECK_IP = "192.0.2.1";

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Serves each action once over a loopback socket and reports how it went.
 *
 * Config validation proves an option is well-formed, not that the action built from it
 * answers a request: the chaos `randomInt` throw and the large-payload spin both passed
 * validation and broke only once traffic arrived. This runs the whole class ahead of
 * time, including custom actions the config layer never sees.
 *
 * Each action gets a throwaway blocklist, so `block` changes nothing real. An action that
 * spins synchronously blocks the event loop and so blocks this check too; the config
 * layer rejects the settings known to cause that. An error raised after the budget
 * (from a held action) is not reported.
 */
export async function checkResponseActions(actions: ResponseAction[], options: CheckResponseActionsOptions = {}): Promise<ResponseCheckResult[]> {
  const budgetMs = options.budgetMs ?? 1500;
  const errors = new Map<number, string>();
  const recordError = (index: number, error: unknown): void => {
    if (!errors.has(index)) errors.set(index, describeError(error));
  };

  const server = http.createServer((req, res) => {
    const index = Number((req.url ?? "").slice(1));
    const action = actions[index];
    if (!action) {
      res.statusCode = 404;
      res.end();
      return;
    }
    const detection: Detection = { detectorId: "response-check", reason: "response action check", score: 1 };
    const ctx: ResponseContext = {
      res,
      detection,
      detections: [detection],
      ip: CHECK_IP,
      path: "/.env",
      totalScore: 0,
      tracker: new IpTracker(CHECK_IP, 60_000),
      blocklist: new MemoryBlocklist(),
      onError: (error) => recordError(index, error),
    };
    Promise.resolve()
      .then(() => action.execute(ctx))
      .then(() => {
        if (!res.writableEnded && !res.destroyed) res.end();
      })
      .catch((error: unknown) => {
        recordError(index, error);
        if (res.destroyed) return;
        if (!res.headersSent) res.statusCode = 500;
        if (!res.writableEnded) res.end();
      });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  const { port } = server.address() as AddressInfo;

  const results: ResponseCheckResult[] = [];
  try {
    for (let i = 0; i < actions.length; i += 1) {
      results.push(await checkOne(port, i, actions[i]!.id, budgetMs, errors));
    }
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  return results;
}

function checkOne(port: number, index: number, id: string, budgetMs: number, errors: Map<number, string>): Promise<ResponseCheckResult> {
  return new Promise((resolve) => {
    let status: number | undefined;
    let settled = false;
    const finish = (outcome: "ok" | "held"): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const error = errors.get(index);
      const result: ResponseCheckResult = { id, outcome: error !== undefined ? "failed" : outcome };
      if (status !== undefined) result.status = status;
      if (error !== undefined) result.error = error;
      resolve(result);
    };

    const req = http.get({ host: "127.0.0.1", port, path: `/${index}`, agent: false }, (res) => {
      status = res.statusCode;
      res.on("error", () => undefined);
      res.on("end", () => finish("ok"));
      res.resume();
    });
    // A connection the action closed itself, with no error reported, is its choice.
    req.on("error", () => finish("ok"));
    const timer = setTimeout(() => {
      finish("held");
      req.destroy();
    }, budgetMs);
  });
}
