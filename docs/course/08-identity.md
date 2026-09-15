# Lesson 8 — Identity and crawler verification

**Goal:** refute a forged Googlebot, confirm a real one, and see why a resolver having a bad
afternoon must never look like an accusation.

← [Course](index.md) · Prev: [Traps and honeytokens](07-traps-and-honeytokens.md) · Next: [Actors and volume](09-actors-and-volume.md)

---

## A name is a claim

Scanners claim to be Googlebot. A request with a Googlebot User-Agent is waved through by a
lot of infrastructure, and a honeypot that believed every crawler claim is one a scanner
walks past by changing one header.

But the claim is checkable. Search operators publish how to verify their crawlers, and a
claim that fails the check is **proof**: the client named a specific, verifiable third party
and was not it. `crawler-verification` makes that check. It is off by default, because it
makes DNS lookups.

## Do this

The detector takes a `resolver`. In production you leave it out and get Node's resolver
behind a cache. Here you inject one, so the lesson runs offline and you decide exactly what
DNS says.

`pantry/lesson-08.mjs`:

```js
import { CrawlerRanges, HoneypotEngine, crawlerVerificationDetector } from "@osqd/hackerpot";

// DNS as Pantry's resolver would answer it. Anything absent is NXDOMAIN.
const PTR = { "66.249.66.1": ["crawl-66-249-66-1.googlebot.com"], "203.0.113.99": ["vps-99.cheap-hosting.example"] };
const A = { "crawl-66-249-66-1.googlebot.com": ["66.249.66.1"] };
const nx = () => Object.assign(new Error("not found"), { code: "ENOTFOUND" });
let dnsDown = false;
const resolver = {
  async reverse(ip) {
    if (dnsDown) throw Object.assign(new Error("timed out"), { code: "ETIMEDOUT" });
    if (!PTR[ip]) throw nx();
    return PTR[ip];
  },
  async resolveAddresses(name) {
    if (!A[name]) throw nx();
    return A[name];
  },
};

const ranges = new CrawlerRanges();
ranges.update("gptbot", ["192.0.2.0/24"]);

const engine = new HoneypotEngine({ extraDetectors: [crawlerVerificationDetector({ resolver, ranges })] });

const GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const GPTBOT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot";

async function claim(label, ip, userAgent) {
  const r = await engine.evaluate({ method: "GET", path: "/recipes/42", query: {}, headers: { host: "pantry.example", "user-agent": userAgent }, ip });
  const v = r.detections.find((d) => d.detectorId === "crawler-verification");
  console.log(`${label.padEnd(28)} ${v ? `certain=${v.certain} +${v.score} ${v.reason}` : "no detection"}`);
}

await claim("Googlebot, Google's address", "66.249.66.1", GOOGLEBOT);
await claim("Googlebot, a VPS", "203.0.113.99", GOOGLEBOT);
await claim("Googlebot, no PTR at all", "203.0.113.98", GOOGLEBOT);
dnsDown = true;
await claim("Googlebot, resolver down", "203.0.113.97", GOOGLEBOT);
await claim("GPTBot, inside its ranges", "192.0.2.5", GPTBOT);
await claim("GPTBot, outside them", "203.0.113.96", GPTBOT);
```

### Checkpoint

```
Googlebot, Google's address  no detection
Googlebot, a VPS             certain=true +10 Claims to be Googlebot, but DNS refutes it: PTR record vps-99.cheap-hosting.example is not under googlebot.com, google.com, googleusercontent.com
Googlebot, no PTR at all     certain=true +10 Claims to be Googlebot, but DNS refutes it: the address has no PTR record, which every operator of a verifiable crawler publishes
Googlebot, resolver down     no detection
GPTBot, inside its ranges    no detection
GPTBot, outside them         certain=true +10 Claims to be GPTBot, but the address is outside every range its operator publishes
```

Two "no detection" lines, meaning opposite things. The first is a **verified** crawler. The
fourth is **no answer**, and no answer proves nothing.

## How forward-confirmed reverse DNS works

Three steps, and the third is the one people skip:

1. **Reverse.** Look up the PTR record for the client's address → `crawl-66-249-66-1.googlebot.com`
2. **Check the domain.** Is it under a domain the operator publishes? → `googlebot.com`, yes
3. **Forward.** Resolve that hostname. Does the original address come back?

Anyone can set a PTR record for their own address to `crawl-1.googlebot.com`. Nobody but
Google can make `crawl-1.googlebot.com` resolve to it. Step 3 is what makes it proof.

| Outcome | Result |
| ------- | ------ |
| verified | no detection; the request is marked a verified crawler |
| hostname outside the domains, or forward lookup disagrees | detection, score 10, **`certain`** |
| no PTR record | refuted, by default: every listed operator publishes PTR records |
| a timeout or resolver failure | **nothing** |

That last row is a design decision, not an omission. A lookup that failed proves nothing,
and "our resolver was briefly unhappy" must never become "we flagged Googlebot".

## What verified buys

A confirmed crawler is exempt from `rate-spike` and `path-bruteforce`: it crawls fast and
visits many distinct paths by design. It is **not** exempt from anything else. A real
Googlebot fetching `/.env` because somebody posted the link is still a fetch of `/.env`.

Verification says who a client is, not whether you want it. That is a policy question.

## Published ranges

Several operators publish the address blocks their crawlers use, and GPTBot, OAI-SearchBot,
ChatGPT-User and DuckDuckBot publish **only** ranges — there is no DNS proof for them at
all. Where a list exists it is the better check: a set lookup instead of two DNS round
trips.

The library ships the URLs of those lists, never the data, because a range baked into a
release is wrong by the time you install it — and wrong here means verifying whoever has
since been handed the address. In production you refresh them on a timer, which makes
outbound HTTPS requests and is therefore opt-in:

```js
import { CrawlerRanges, startCrawlerRangeRefresh } from "@osqd/hackerpot";

const ranges = new CrawlerRanges();
const stop = startCrawlerRangeRefresh(ranges);   // twice a day by default
```

A list decides who is verified, so a list that arrived wrong would verify whatever it
covered. `update` refuses the dangerous shapes outright. `pantry/lesson-08b.mjs`:

```js
import { CrawlerRanges } from "@osqd/hackerpot";
const ranges = new CrawlerRanges();
for (const list of [[], ["10.0.0.0/7"], ["192.0.2.0/24", "not-an-address"]]) {
  try {
    ranges.update("gptbot", list);
    console.log(JSON.stringify(list), "->", ranges.list().map((r) => `${r.id}: ${r.prefixes} prefixes`).join(""));
  } catch (error) {
    console.log(JSON.stringify(list), "->", error.message);
  }
}
```

### Checkpoint

```
[] -> the list is empty
["10.0.0.0/7"] -> "10.0.0.0/7" covers more of the internet than any crawler owns; refusing the whole list
["192.0.2.0/24","not-an-address"] -> gptbot: 1 prefixes
```

An empty list and a block wider than any crawler owns are refused **whole**, leaving the
previous list in place. An unparseable entry is dropped and the rest kept.

## Exercise

Feedly's feed fetcher sends
`Feedly/1.0 (+http://www.feedly.com/fetcher.html; like FeedFetcher-Google)`. It mentions a
Google crawler, from an address Google's DNS will certainly disown. Predict what fires, then
check with a resolver that answers NXDOMAIN to everything.

<details>
<summary>Checkpoint</summary>

```js
import { HoneypotEngine, crawlerVerificationDetector } from "@osqd/hackerpot";
const resolver = { async reverse() { throw Object.assign(new Error("nx"), { code: "ENOTFOUND" }); }, async resolveAddresses() { throw Object.assign(new Error("nx"), { code: "ENOTFOUND" }); } };
const engine = new HoneypotEngine({ extraDetectors: [crawlerVerificationDetector({ resolver })] });
const r = await engine.evaluate({ method: "GET", path: "/feed.xml", query: {}, headers: { host: "pantry.example", "user-agent": "Feedly/1.0 (+http://www.feedly.com/fetcher.html; like FeedFetcher-Google)" }, ip: "203.0.113.95" });
console.log(r.detections.map((d) => d.detectorId).join(", ") || "nothing fired");
```

```
nothing fired
```

**Nothing.** A crawler name introduced by "like" is a comparison, not an identity, and the
detector skips it. Read as a claim, it would be proof of impersonation, and a feed reader
would be blocked for being honest about what it resembles. Pantry wants its recipes in
people's feed readers.
</details>

## What you learned

- A crawler name is a claim, and a refuted claim is proof
- Forward-confirmed reverse DNS is three steps; the forward step is what makes it proof
- A failed lookup proves nothing and flags nothing
- A verified crawler skips the volume detectors and nothing else
- Published ranges ship as URLs, refresh opt-in, and wrong-shaped lists are refused whole

## Where to read more

- [Verifying crawlers](../detection/verification.md) — every crawler, ranges, custom resolvers
- [The detectors](../detection/detectors.md#crawler-verification) — its options
- [Threat model](../concepts/threat-model.md#crawler-impersonation)

Next: [Actors and volume](09-actors-and-volume.md).
