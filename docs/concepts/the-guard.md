# The proof guard

Why a block in front of real users needs proof, and what counts as proof. If you read one page, read this one.

← [Documentation](../index.md)

---

A `block` is not a response to one request. It writes the address to the blocklist, and to
the firewall if an [enforcer](../operations/firewall.md) is wired, so **every later request
from that address is refused, your application's own pages included.** Standalone, where
nothing legitimate should arrive, that is the point. In front of a real application it is
the most expensive mistake the library can make.

And scores are sums of guesses. A scripting User-Agent is suspicious, and it is also every
monitoring script. A burst of distinct paths is enumeration, and it is also one page load of
a modern single-page app. A shared browser fingerprint across several flagged addresses is
rotation, and it is also three people on the same browser build. Each of those, before it
was fixed, reached the default block threshold for ordinary visitors. Points do not compose
into proof.

## Proof versus suspicion

So detections are in two tiers:

| | Proof (`certain: true`) | Suspicion |
| --- | --- | --- |
| What it rests on | something no legitimate client can produce | a pattern attackers usually show |
| Can it be wrong about a real visitor? | only if the deployment broke its own guarantee | yes |
| Adds to the score | yes | yes |
| Can make a middleware block stick | **yes** | **no** |

## What the guard does

It runs **after** the policy chooses and before the action runs:

```ts
if (actionId === "block" && blockRequiresProof && !detections.some((d) => d.certain === true)) {
  downgradedFrom = "block";
  actionId = unprovenBlockFallback;        // "tarpit" by default
}
```

A downgraded request gets the fallback for that one request, nothing is blocklisted, and
the hit records `downgradedFrom: "block"`. The next request from the address is evaluated
again, and blocked the moment it carries proof.

It lives in the engine rather than in a policy, so it cannot be forgotten in a custom
policy, worked around by one, or bypassed by someone who has not read this page.

## Where it is on

| Front end | Default |
| --- | --- |
| `createMiddleware`, `koaHoneypot`, `fastifyHoneypot`, `fetchHoneypot`, `withFetchHoneypot`, `trapFormGuard` | **on** |
| `hackerpot replay` and `replayLog` | on (a log comes from an application serving real users) |
| `HoneypotServer`, the standalone service | off: nothing legitimate reaches it |
| `engine.evaluate()` called directly | off, unless you pass `blockRequiresProof: true` |

```ts
app.use(createMiddleware(engine));                                        // guard on, tarpit fallback
app.use(createMiddleware(engine, { unprovenBlockFallback: "rate-limit" })); // a different fallback
app.use(createMiddleware(engine, { blockRequiresProof: false }));         // block on score, as standalone does
```

**The fallback cannot be `block`.** `createMiddleware` throws if you try, because a block
fallback would make every downgrade block the request the downgrade existed to protect,
while still recording it as a guard refusal, so the metric meant to catch this would report
success.

## What counts as proof

Five things, each for a stated reason.

1. **A replayed honeytoken** (`honeytoken`). A fake credential you planted. No legitimate
   client has ever been given it, so possessing it means reading something that was only
   ever bait. See [honeytokens](../detection/traps-and-honeytokens.md#honeytokens).
2. **A hidden trap** (`trap`). A link or form field in your markup that no sequence of
   clicks, keystrokes or screen-reader gestures reaches, and that robots.txt disallows.
   Detection by construction. See [traps](../detection/traps-and-honeytokens.md#hidden-traps).
3. **A protocol violation no client stack emits** (`header-integrity`): a repeated `Host`
   or `Content-Length`, or a connection-specific header over HTTP/2 or HTTP/3. A client that
   sends one cannot talk to a compliant proxy, so no shipping client does, and the repeated
   framing headers are what request smuggling is built on.
4. **A self-declared attack tool** (`scanner-signature`): `sqlmap`, `nikto`, `nmap`,
   `masscan`, `gobuster`, `ffuf`, `nuclei`, `acunetix`, `metasploit`, `hydra`, `burpsuite`
   and the rest of `attackToolUserAgentPatterns`. The client said what it is, and nobody
   harmed by being believed is honest. A bare `curl`, `wget`, `python-requests` or
   `Go-http-client` is **only suspicion**: that is every legitimate script and integration.
   Patterns you add with `extraPatterns` are suspicion too.
5. **A refuted crawler claim** (`crawler-verification`): a User-Agent claiming Googlebot or
   another verifiable crawler, from an address whose forward-confirmed reverse DNS or
   published range list says otherwise. A DNS timeout proves nothing and flags nothing. See
   [verification](../detection/verification.md).

## What does not

Everything else, including findings that look conclusive:

- **A request for `/.env`.** No link leads there, but a URL is client-supplied text, and the
  client typing it might be your own security engineer. Decoys score; they do not prove.
- **An injection payload.** Real users paste strange strings into search boxes, and the
  false-positive suite exists because `union station` and `drop off locations` are real
  queries.
- **Volume.** A corporate NAT, a university and a mobile carrier's CGNAT pool all present
  hundreds of people as one address.
- **A missing header.** A header missing from a request might have been stripped by a proxy
  in between, and one missing from a log line was never recorded.
- **Correlation across addresses.** `repeat-actor` confirms that suspicious addresses share
  a fingerprint; a fingerprint is shared by every user of one browser build.

When you [write a detector](../detection/writing-a-detector.md), the test for `certain` is
whether you can write down why no legitimate client could produce the finding. If you
cannot, it is suspicion.

## Watching it

`hackerpot_downgrades_total` on [`/metrics`](../operations/metrics.md) counts refused
blocks, and it is the series worth alerting on. A rising count means scores are reaching
the block threshold on evidence that proves nothing, which is exactly how real visitors
end up blocked when the guard is off. The [traffic audit](../operations/audit.md) raises
`downgrade-spike` when refusals jump against the baseline.

A downgrade is not a failure of the guard: it is the guard working. It is a reason to read
which detectors are adding up, in the [dashboard](../operations/dashboard.md) or with
[`hackerpot explain`](../testing/cli.md#explain).

## Related

- [Scores and escalation](scoring.md) — the ladder the guard sits on
- [The detectors](../detection/detectors.md) — which ones can be proof
- [Design decisions](../design/decisions.md#blocks-in-middleware-need-proof) — the trade, recorded
