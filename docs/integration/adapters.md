# Adapters

Express and Connect, Koa, Fastify, Fetch handlers, trap forms, and failing open.

← [Documentation](../index.md) · [Integration](index.md)

---

```ts
import { createMiddleware, fastifyHoneypot, koaHoneypot, trapFormGuard, withFetchHoneypot } from "@osqd/hackerpot/adapters";

app.use(createMiddleware(engine));                          // Express, Connect, node:http with next()
koa.use(koaHoneypot(engine));                               // Koa: mount it first
fastify.addHook("onRequest", fastifyHoneypot(engine));      // Fastify: the earliest hook
export default { fetch: withFetchHoneypot(engine, app.fetch) };  // Hono, Next.js route handlers, Fetch-shaped handlers
```

Everything here is also exported from `@osqd/hackerpot`. The separate path exists so a deployment that
imports only one adapter can say so.

All of them share one implementation, `createMiddleware`, so they share its behaviour: the two-pass body
evaluation, the proof guard, 404 gating for `path-bruteforce`, the allowlist and service tokens, and
failing open.

## Options

| Option | Default | |
| --- | --- | --- |
| `blockRequiresProof` | `true` | a `block` runs only with a `certain` detection; see [the proof guard](../concepts/the-guard.md) |
| `unprovenBlockFallback` | `"tarpit"` | what an unproven block becomes; cannot be `"block"` (throws) |
| `failOpen` | `true` | an internal error calls `next()`; `false` calls `next(err)` |
| `countOnlyMissedPaths` | `true` | a path your app serves counts toward `path-bruteforce` only once it answers 404 |

## Express and Connect

```ts
import express from "express";
import { HoneypotEngine, createMiddleware, hardenHttpServer } from "@osqd/hackerpot";

const engine = new HoneypotEngine({ onHit: (hit) => console.warn("[honeypot]", hit.ip, hit.respondedWith) });
const app = express();
app.use(createMiddleware(engine));   // mount FIRST
// ...your routes
hardenHttpServer(app.listen(3000));
```

With plain `node:http`, call it with a `next` callback:

```ts
const honeypot = createMiddleware(engine);
http.createServer((req, res) => {
  void honeypot(req, res, (err) => {
    if (err) console.error("[honeypot]", err);   // only with failOpen: false
    app(req, res);                               // your application
  });
});
```

**Mount it before your body parser.** A request no detector flags falls through with its stream
unread, so your parser still gets it. A parser mounted first would have consumed the body, and the
honeypot's body detectors would see nothing.

**Harden your listener.** In middleware mode the server is yours, so Node's permissive defaults stand
unless you call `hardenHttpServer(server)`: a 20 s headers deadline, a 30 s request deadline, 5 s
keep-alive, a 60 s socket timeout and a 10,000-connection cap. The values are deliberately not
configurable; no legitimate request needs 20 s to send its headers.

`dispatch(engine, res, result, ip, path)` runs a response for an `EvaluationResult`, for a front end of
your own.

## Koa

```ts
import Koa from "koa";
import { koaHoneypot } from "@osqd/hackerpot";

const koa = new Koa();
koa.use(koaHoneypot(engine));        // first
```

It works on Koa's raw `ctx.req` and `ctx.res`. When the honeypot answers, it sets `ctx.respond = false`
and does not call `next()`, so nothing downstream runs and Koa writes nothing over the answer. The 404
gating reads the final status from the raw response when it finishes, which Koa writes after the whole
chain. Koa is not a dependency.

## Fastify

```ts
import Fastify from "fastify";
import { fastifyHoneypot } from "@osqd/hackerpot";

const fastify = Fastify();
fastify.addHook("onRequest", fastifyHoneypot(engine));
```

`onRequest` is the earliest hook, so the body is still unread: the honeypot reads it only for a request
it is answering, and Fastify's parser gets an intact stream otherwise. When the honeypot answers, the
reply is hijacked, so Fastify neither routes the request nor tries to send a second response. Fastify is
not a dependency.

## Fetch handlers

For handlers shaped `(request: Request) => Response` (Hono, Next.js route handlers and the like), on a
Node-compatible runtime:

```ts
import { withFetchHoneypot } from "@osqd/hackerpot";

// Wraps your handler: probes get the honeypot's Response, everything else yours.
const handle = withFetchHoneypot(engine, app.fetch);
const response = await handle(request, { ip: clientAddress });
```

`fetchHoneypot(engine)` is the unwrapped form: it resolves to the honeypot's `Response`, or `undefined`
for a request your handler should answer.

```ts
const honeypot = fetchHoneypot(engine);
const handled = await honeypot(request, { ip });
if (handled) return handled;
return app.fetch(request);
```

Prefer the wrapper: only it learns your handler's status, which the 404 gating needs.

What to know:

- **Pass the client IP.** A `Request` carries none. Without it every request shares one address, and
  with `trustProxy` the engine falls back to `X-Forwarded-For`. See [the client IP](client-ip.md).
- **Streaming works.** `drip-feed` and `large-payload` stream through a `ReadableStream` with
  backpressure, and an aborted request (its `signal`) releases a tarpit at once.
- **Bodies are read lazily.** A request passed to your handler still has a readable body.
- **`Host` is restored from the URL** when the runtime dropped it, so `header-anomaly` does not flag
  every request for something the runtime removed.
- **The fingerprint is weaker.** Fetch runtimes normalise header order, so the
  [actor fingerprint](../concepts/actors.md#the-actor-fingerprint) has less to work with, and
  `header-integrity` cannot see repeated headers.
- **Node built-ins are required.** Edge runtimes without them are not supported.

## Trap forms

A hidden trap field in a POST form arrives in the body, which the middleware reads only for requests
something already flagged. `trapFormGuard(engine)` checks it after your parser:

```ts
app.post("/signup", express.urlencoded({ extended: false }), trapFormGuard(engine), signup);
```

See [traps](../detection/traps-and-honeytokens.md#trapformguard).

## Failing open

If the honeypot's own machinery throws before it has started answering (a Redis blocklist that is down,
a socket that died), the middleware reports the error through the engine's `onError` with source
`"middleware"` and calls `next()`. The request reaches your routes as if the honeypot were not there.

A honeypot that can take its host application down is worse than no honeypot. An async middleware that
rejects is not caught by Express 4 at all: the request just hangs until it times out. So nothing in the
middleware rejects into your application.

Details:

- **`failOpen: false`** passes the error to `next(err)`, for your error handler to see.
- **Once the honeypot has started answering**, the application cannot render an error page over it, so
  the middleware ends the response itself.
- **`next` runs at most once**, even if your `next` throws synchronously.
- **Detectors, the store, the enricher and `onHit` never reach this path**: the engine isolates each.
- **A slow asynchronous detector** past `detectorTimeoutMs` (default 2000) is skipped for that request
  and reported, so one detector cannot hold requests open.

`trapFormGuard` fails open the same way.

## `path-bruteforce` in front of real users

In middleware mode the engine sees every request your app serves, static assets included, and one
ordinary page load of a modern single-page app is easily twenty distinct paths, past `path-bruteforce`'s
default of 15 in 30 s. Before this was fixed, that blocked a real visitor for loading a page.

So in middleware mode **a path handed to your app counts toward `path-bruteforce` only once your app
answers it 404**. A path the honeypot answers itself always counts. A wordlist walk still trips it, from
the request after the threshold, because a 404 is known only once your app has answered; a page load does
not.

`rate-spike` (60 requests in 10 s) and `credential-bruteforce` still count every request: raw volume and
repeated attempts on one path are what they measure. Raise `rate-spike`'s threshold if one of your pages
makes sixty requests.

**If your app answers unknown paths with 200** (a single-page app's history fallback serving
`index.html` for every route, or a catch-all route), it never produces a miss, so `path-bruteforce`
cannot fire on paths your app answers. Decoys and the per-request detectors still catch most probes. To
catch the enumeration itself, count every path as standalone does, and raise the threshold well above
your heaviest page:

```ts
app.use(createMiddleware(engine, { countOnlyMissedPaths: false }));
```

```toml
[detectors.path-bruteforce]
unique_path_threshold = 60
```

## Mount the dashboard outside it

If you mount [the dashboard](../operations/dashboard.md) on the same server with
`createDashboardHandler`, mount it **outside** the honeypot middleware, so reading the dashboard never
shows up in it.

## A front end of your own

The pieces `createMiddleware` is built from are exported: `engine.resolveIp`, `engine.isAllowlisted`,
`engine.serviceTokenFor`, `engine.isBlocked`, `engine.evaluate(facts, options)`, `dispatch`, and the
request helpers `pathOf`, `parseQuery` (a null-prototype bag), `mayHaveBody` and `readBody` (capped at
`MAX_BODY_BYTES`, 64 KB). Evaluate headers first with `recordHit: false`, read the body only if
something fired, and evaluate again with `trackActivity: false`, so the request is committed exactly
once. See [how it works](../concepts/how-it-works.md#two-passes-so-a-body-is-never-read-for-nothing).

## Related

- [The client IP](client-ip.md) — do this before deploying behind a proxy
- [The proof guard](../concepts/the-guard.md) — `blockRequiresProof`
- [Your first integration](../start/first-integration.md)
