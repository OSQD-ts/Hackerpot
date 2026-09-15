# Lesson 10 — In front of an app

**Goal:** put the honeypot in front of a running Pantry, and get right the three things
that are dangerous to get wrong there: the client address, your own monitors, and forms.

← [Course](index.md) · Prev: [Actors and volume](09-actors-and-volume.md) · Next: [The standalone service and protocol honeypots](11-standalone-and-protocols.md)

---

## The middleware

```js
import { HoneypotEngine, createMiddleware } from "@osqd/hackerpot";

const engine = new HoneypotEngine();
app.use(createMiddleware(engine));   // mount it FIRST
```

`createMiddleware` is Express and Connect middleware, and plain `node:http` with a `next`
callback. It does everything from lessons 1–9 for real: it evaluates, runs the chosen
response on the actual socket, reads a body only when something fired, and passes
everything else to `next()` with its body unread. Three defaults make it safe in front of
real visitors:

1. **A block needs proof** — the guard from [lesson 4](04-the-guard.md), on by default.
2. **It fails open.** If the honeypot's own machinery throws (a Redis that is down, say),
   the error goes to `onError` and the request continues to Pantry.
3. **A served path is not enumeration** until Pantry answers it 404 — [lesson 9](09-actors-and-volume.md).

## Do this

A small Pantry on `node:http`, with the honeypot in front of it, and a script playing six
clients against it.

`pantry/lesson-10.mjs`:

```js
import http from "node:http";
import {
  HoneypotEngine, createMiddleware, hardenHttpServer,
  renderTrapField, renderTrapLink, trapDetector, trapFormGuard,
} from "@osqd/hackerpot";

const engine = new HoneypotEngine({
  // The script below plays several clients from one machine by sending X-Forwarded-For.
  // In production this is true ONLY behind a proxy that overwrites that header.
  trustProxy: true,
  serviceTokens: { tokens: { "uptime-monitor": "monitor-3f9a1c7e5b2d4a60" } },
  extraDetectors: [trapDetector({ paths: ["/internal/export.csv"], formFields: ["website"] })],
  onHit: (hit) => console.log(`  [hit] ${hit.ip} ${hit.method} ${hit.path} -> ${hit.respondedWith}`),
});

const honeypot = createMiddleware(engine);
const checkTraps = trapFormGuard(engine);

// Pantry itself: a home page, a signup form, a health check.
function pantry(req, res) {
  if (req.url === "/") return res.end(`<h1>Pantry</h1>${renderTrapLink("/internal/export.csv")}`);
  if (req.url === "/healthz") return res.end("ok");
  if (req.url === "/signup" && req.method === "GET") return res.end(`<form method="post">${renderTrapField("website")}<input name="email"></form>`);
  if (req.url === "/signup" && req.method === "POST") {
    let text = "";
    req.on("data", (chunk) => (text += chunk));
    req.on("end", () => {
      req.body = Object.fromEntries(new URLSearchParams(text));   // your body parser
      checkTraps(req, res, () => {                                  // then the trap check
        res.writeHead(303, { location: "/welcome" }).end();
      });
    });
    return;
  }
  res.writeHead(404).end("Not Found");
}

const server = http.createServer((req, res) => void honeypot(req, res, () => pantry(req, res)));
hardenHttpServer(server);
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;

const BROWSER = { "user-agent": "Mozilla/5.0 (Macintosh) Chrome/126.0.0.0 Safari/537.36", accept: "text/html", "accept-language": "en-GB", "accept-encoding": "gzip" };

async function send(label, path, { from, headers = {}, method = "GET", body } = {}) {
  const response = await fetch(base + path, { method, body, redirect: "manual", headers: { "x-forwarded-for": from, ...headers } });
  const text = await response.text();
  console.log(`${label.padEnd(34)} ${response.status} ${text.split("\n")[0].slice(0, 40)}`);
}

await send("reader: home page", "/", { from: "198.51.100.1", headers: BROWSER });
await send("scanner: /.env", "/.env", { from: "203.0.113.5", headers: { "user-agent": "curl/8.4.0" } });
await send("monitor without its token", "/healthz", { from: "192.0.2.10", headers: { "user-agent": "curl/8.4.0" } });
await send("monitor with its token", "/healthz", { from: "192.0.2.11", headers: { "user-agent": "curl/8.4.0", "x-hackerpot-token": "monitor-3f9a1c7e5b2d4a60" } });
await send("reader: signs up", "/signup", { from: "198.51.100.2", method: "POST", headers: { ...BROWSER, "content-type": "application/x-www-form-urlencoded" }, body: "email=ada%40example.com&website=" });
await send("form bot: fills every field", "/signup", { from: "203.0.113.6", method: "POST", headers: { ...BROWSER, "content-type": "application/x-www-form-urlencoded" }, body: "email=bot%40spam.example&website=https%3A%2F%2Fseo.example" });

server.close();
```

The server listens on port 0, so the operating system picks a free port, and the script
closes it at the end.

### Checkpoint

```
reader: home page                  200 <h1>Pantry</h1><a href="/internal/export
  [hit] 203.0.113.5 GET /.env -> decoy-content
scanner: /.env                     200 APP_ENV=production
  [hit] 192.0.2.10 GET /healthz -> not-found
monitor without its token          404 
monitor with its token             200 ok
reader: signs up                   303 
  [hit] 203.0.113.6 POST /signup -> tarpit
form bot: fills every field        404 Not Found
```

The last request takes a few seconds: it is being tarpitted.

## Reading it

**The reader** reached Pantry, and nothing was recorded.

**The scanner** got a `200` and a fake `.env`. From its side, the probe worked.

**The monitor without its token** is the lesson's warning. An uptime monitor is a bare
HTTP client with a scripting User-Agent, which is exactly what `scanner-signature` looks
for, so the honeypot answered it a 404 and Pantry's health check reports Pantry down.

**The monitor with its token** went straight through: a valid service token exempts a
request like an allowlisted address — no detection, no score, no record anywhere.

**The form bot** had a perfect browser disguise, so the middleware found nothing on its
headers and handed the POST to Pantry. Pantry parsed the body, and `trapFormGuard` found
the hidden `website` field filled and answered the request itself. Order matters: **your
body parser first, then `trapFormGuard`, then your handler.**

## The client address

Stop here if Pantry sits behind anything: nginx, a load balancer, a CDN.

The resolved address is what the allowlist exempts, the score accumulates against, the
blocklist blocks and the IOC feed publishes. `trustProxy` decides where it comes from:

| `trustProxy` | The address is |
| --- | --- |
| `false` (default) | the socket's remote address. `X-Forwarded-For` is ignored entirely |
| `true` | the **leftmost** `X-Forwarded-For` entry, if it parses as an address |

This lesson turned it on so that one script could play six clients. That is precisely the
danger: **any client can send that header.** With `trustProxy` on and nothing overwriting
the header, an attacker escapes its score by sending a new address with every request,
impersonates an allowlisted address to skip detection, or probes with a victim's address
until the victim is blocked and published.

Turn it on **only** when every request reaches Pantry through a proxy you control that
**overwrites** the header, and Pantry's port is not reachable around it:

```nginx
proxy_set_header X-Forwarded-For $remote_addr;    # overwrite, never append
```

Get it wrong in the other direction — behind a proxy with it off — and every visitor shares
the proxy's address and score, until the honeypot blocks the proxy. Neither failure errors
or logs.

## Service tokens, rather than allowlisting the monitor

An allowlist entry works when the monitor has a fixed address. Hosted monitors do not. A
token does not depend on the address, is compared in constant time, and never appears in a
log or a store. Give each monitor its own, at least 16 random characters, and serve it over
TLS: a shared secret in a header is replayable by anyone who sees it once.

## Other frameworks

Every adapter is the same middleware underneath, so everything above holds for each:

```js
import { createMiddleware, fastifyHoneypot, koaHoneypot, withFetchHoneypot } from "@osqd/hackerpot/adapters";

app.use(createMiddleware(engine));                              // Express, Connect, node:http
koa.use(koaHoneypot(engine));                                   // Koa: first
fastify.addHook("onRequest", fastifyHoneypot(engine));          // Fastify: the earliest hook
export default { fetch: withFetchHoneypot(engine, app.fetch) }; // Hono, Next.js route handlers
```

On a Fetch runtime there is no socket, so pass the address the platform gives you:
`handle(request, { ip })`.

## Harden the listener

In middleware mode the server is yours, so Node's permissive defaults stand — no connection
cap, a five-minute request timeout — unless you call `hardenHttpServer(server)`. It sets a
20 s headers deadline, a 30 s request deadline, a 5 s keep-alive, a 60 s socket timeout and
a 10,000-connection cap. Do it on anything internet-facing.

## Exercise

Pantry is deployed behind nginx with `trustProxy: true`, and nginx overwrites
`X-Forwarded-For` correctly. Six months later somebody publishes Pantry's port directly on
the host so they can debug it. Nothing looks broken. What has changed?

<details>
<summary>Answer</summary>

Anyone who finds the port now reaches Pantry **around** nginx, so nothing overwrites the
header, and `trustProxy: true` believes whatever they send. They can pick their own address
on every request: escape any score, claim an allowlisted address, or get an arbitrary victim
blocked — and, with [firewall enforcement](../operations/firewall.md), firewalled.

Nothing errors and nothing logs. The only signs are in the data: an incident from an address
you know you did not send from. The fix is to make the listener unreachable except through
the proxy, not to hope nobody finds it. The compose file in [lesson 13](13-scaling.md) keeps
`TRUST_PROXY=false` for exactly this reason: it publishes the honeypot's port straight to
the host.
</details>

## What you learned

- `createMiddleware` runs everything for real, fails open, and needs proof to block
- A bare-client monitor looks like a scanner; give it a service token
- A POST form's trap needs your body parser, then `trapFormGuard`, then your handler
- `trustProxy` is the highest-consequence setting, and both wrong directions are silent
- Harden a listener you own with `hardenHttpServer`

## Where to read more

- [Adapters](../integration/adapters.md) — every front end, options, failing open
- [The client IP](../integration/client-ip.md) — read before deploying behind anything
- [Service tokens](../integration/service-tokens.md) · [Your first integration](../start/first-integration.md)

Next: [The standalone service and protocol honeypots](11-standalone-and-protocols.md).
