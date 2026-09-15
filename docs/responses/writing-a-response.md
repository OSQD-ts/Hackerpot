# Writing a response

The action contract, and the resource bounds a new one must keep.

← [Documentation](../index.md) · [Responses](index.md)

---

```ts
import { HoneypotEngine, type ResponseAction, type ResponseContext } from "@osqd/hackerpot";

export function teapotAction(): ResponseAction {
  return {
    id: "teapot",
    description: "Answer 418",
    execute(ctx: ResponseContext): void {
      ctx.res.statusCode = 418;
      ctx.res.setHeader("Content-Type", "text/plain; charset=utf-8");
      ctx.res.end("I'm a teapot");
    },
  };
}

new HoneypotEngine({ extraResponseActions: [teapotAction()] });
```

Select it from a decoy's `respondWith`, a detector's `respond_with`, or a [policy](policy.md).

## The contract

```ts
interface ResponseAction {
  id: string;
  description?: string;
  execute(ctx: ResponseContext): Promise<void> | void;
}

interface ResponseContext {
  res: ServerResponse;       // write the answer here
  detection: Detection;      // the top detection; its metadata.payload for a decoy
  detections: Detection[];
  ip: string;
  path: string;
  totalScore: number;
  tracker: IpTracker;
  blocklist: Blocklist;      // for actions that block
  onError?: (error: unknown, context: { source: string }) => void;
}
```

`res` is a Node `ServerResponse`. Behind the [Fetch adapter](../integration/adapters.md#fetch-handlers)
it is a shim that supports what the built-in actions use: `statusCode`, `setHeader`, `getHeader`,
`write` (with backpressure), `end`, `headersSent`, `writableEnded`, `destroyed`, and the `close`,
`finish` and `drain` events. Stay within those and an action works everywhere.

If `execute` returns without ending the response, the front end ends it.

## The rules

**Never let a side effect fail the response.** An action that writes to a backend (a blocklist, a
queue) should catch the failure, report it through `ctx.onError`, and still answer. A 500 from a
honeypot is a tell: every other response is plausible.

**Bound what you hold.** An action that delays or streams holds a connection on your side too. Count
active executions and degrade to an immediate answer past a cap, as `tarpit` (1000), `drip-feed` (256)
and `large-payload` (64) do. Otherwise a flood turns your retaliation into your outage.

**Release on disconnect.** Listen for `close` and stop: clear the timer, stop the stream, release the
slot. Check `res.destroyed` before starting, because a client that disconnected before the action began
will never emit `close`, and a slot it holds is held forever.

**Respect backpressure.** When `write()` returns `false`, wait for `drain`. A client that stops reading
should hold a slot, not fill your memory.

**Allocate once.** A large or compressed payload should be built once and reused, not per request, and
its size should be bounded at configuration time, not discovered on the first probe.

**Serve nothing real.** A fake must be invented. Never template real hostnames, real names or real
secrets into a response an attacker receives.

The helpers the built-in actions use are exported: `sleep`, `randomBetween`, and `resolveDelay` for the
`number | [min, max]` delay shape.

## Test it before traffic does

```ts
import { checkResponseActions } from "@osqd/hackerpot";

const results = await checkResponseActions([teapotAction()], { budgetMs: 1500 });
// [{ id: "teapot", outcome: "ok", status: 418 }]
```

Each action is served once over a loopback socket with a throwaway blocklist. `ok` means the response
completed, `held` that it was still delaying or streaming at the budget, and `failed` that it threw,
rejected or reported through `onError`. A deliberate 5xx is not a failure.

## Related

- [Response actions](actions.md) — twelve examples of the contract
- [Writing a detector](../detection/writing-a-detector.md) — the other half
