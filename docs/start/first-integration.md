# Your first integration

Ten lines of middleware in front of an application, and what each one does.

← [Documentation](../index.md)

---

```ts
import express from "express";
import { HoneypotEngine, createMiddleware, hardenHttpServer } from "@osqd/hackerpot";

const engine = new HoneypotEngine({
  allowlist: ["10.0.0.0/8"],                                   // your monitors, office, CI
  onHit: (hit) => console.warn("[honeypot]", hit.ip, hit.path, hit.respondedWith),
});

const app = express();
app.use(createMiddleware(engine));                             // mount FIRST
app.get("/", (_req, res) => res.send("the real app"));
hardenHttpServer(app.listen(3000));
```

That is a working deployment. Against it:

| Request | What happens |
| --- | --- |
| `GET /` from a browser | your route answers; the honeypot recorded nothing |
| `GET /.env` | a convincing fake `.env` is served, and a hit is recorded |
| `GET /.env` with `User-Agent: sqlmap/1.7` | the fake `.env` again, and the hit carries proof |
| `POST /login` with `{"password":{"$ne":null}}` from `curl` | `scanner-signature` fires on the headers, so the body is read, `nosql-injection` fires too, a 404 |
| the same POST from a browser | reaches your route: nothing fired on the headers, so the body was never read (see [two passes](../concepts/how-it-works.md#two-passes-so-a-body-is-never-read-for-nothing)) |
| the same address, a dozen probes later | its score passes 40; a block only if a detection was proof, otherwise a tarpit |
| any request from `10.0.0.0/8` | untouched and unrecorded, whatever it asks for |

## Line by line

**`new HoneypotEngine({...})`** builds the engine with the default detector set (23
detectors), the default response actions, the default escalation policy and an in-memory
store. Every part is replaceable; see the [API reference](../reference/api.md#the-engine).

**`allowlist`** exempts addresses and CIDR ranges from everything: no detection, no score,
no block, no record. It is the single most effective false-positive control. Addresses are
compared by value, so `::ffff:10.1.2.3` matches `10.0.0.0/8`.

**`onHit`** is called with every recorded incident. Wire it to your logger, a queue, or a
[webhook](../operations/webhooks.md). A throwing `onHit` is reported through `onError`
and never reaches the request.

**`createMiddleware(engine)`** is Express and Connect middleware, and plain `node:http`
with a `next` callback. **Mount it before your routes.** A request no detector flags
falls through to `next()` with its body unread, so your own body parser still gets an
intact stream.

**`hardenHttpServer(server)`** applies conservative timeouts and a connection cap. In
middleware mode the listener is yours, so Node's permissive defaults (no connection cap,
a five-minute request timeout) would otherwise stand — a Slowloris invitation on anything
internet-facing. `HoneypotServer` and `ManagementServer` call it on themselves.

## What the middleware promises

Three defaults make it safe in front of real visitors, and each is a deliberate trade:

1. **A block needs proof.** The policy may choose `block` on score, but the middleware
   lets it run only when a detection is `certain`: a replayed honeytoken, a hidden trap, a
   protocol violation, a self-declared attack tool, a refuted crawler claim. Otherwise the
   request is tarpitted and nothing is blocklisted. See [the proof guard](../concepts/the-guard.md).
2. **It fails open.** If the honeypot's own machinery throws (a Redis blocklist that is
   down, say), the error goes to `onError` with source `"middleware"` and the request
   continues to your routes. See [adapters](../integration/adapters.md#failing-open).
3. **Asset paths are not enumeration.** A path your app serves counts toward
   `path-bruteforce` only once your app answers it 404, so one page load's twenty assets
   are not a wordlist walk. See [adapters](../integration/adapters.md#path-bruteforce-in-front-of-real-users).

## Next steps

- **Behind a proxy?** Read [the client IP](../integration/client-ip.md) before anything
  else. Without `trustProxy`, every visitor has the proxy's address; with it wrongly on,
  every visitor can choose theirs.
- **Plant proof.** A [honeytoken](../detection/traps-and-honeytokens.md#honeytokens) in a
  decoy file, and a [trap link](../detection/traps-and-honeytokens.md#hidden-traps) in
  your markup, give the proof guard something to act on.
- **Watch it.** [The dashboard](../operations/dashboard.md) on its own listener, or the
  [management API](../operations/management-api.md).
- **Koa, Fastify, Hono, Next.js?** See [adapters](../integration/adapters.md).
- **Prove it first.** [Replay your access log](../testing/replay.md) through the same
  detectors before any of it is live.

## Related

- [How it works](../concepts/how-it-works.md) — what happens to a request
- [Running it standalone](standalone.md) — the other way to deploy
- [Configuration](../reference/configuration.md) — sharing one TOML file with the service
