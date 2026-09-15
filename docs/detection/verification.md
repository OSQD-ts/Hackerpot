# Verifying crawlers

Forward-confirmed reverse DNS, the address ranges operators publish, and refuting a forgery.

← [Documentation](../index.md) · [Detection](index.md)

---

Scanners claim to be Googlebot. A request with a Googlebot User-Agent is waved through by a
lot of infrastructure, and a honeypot that treats every crawler claim as a crawler is one
that a scanner can walk past by changing one header.

But the claim is checkable. Search operators publish how to verify their crawlers, and a
claim that fails the check is **proof**: the client named a specific, verifiable third party
and was not it. `crawler-verification` makes that check.

It is **off by default** because it makes DNS lookups for every request that claims a known
crawler, and, with published ranges, outbound HTTPS requests on a schedule.

```toml
[detectors.crawler-verification]
enabled = true
published_ranges = true         # also fetch the operators' own address lists
ranges_refresh_hours = 12
treat_missing_ptr_as_forgery = true
```

## Which crawlers

`verifiableCrawlers`, matched by lowercase User-Agent tokens:

| Crawler | Verified by |
| --- | --- |
| Googlebot (and Google-InspectionTool, Storebot-Google, GoogleOther, Google-Extended, AdsBot-Google, Mediapartners-Google, FeedFetcher-Google) | DNS (`googlebot.com`, `google.com`, `googleusercontent.com`) and published ranges |
| Bingbot (and AdIdxBot, MSNBot, BingPreview) | DNS (`search.msn.com`) and published ranges |
| Applebot, YandexBot, Baiduspider, Yahoo! Slurp, Sogou, SeznamBot, Naver Yeti, PetalBot, Coc Coc, AhrefsBot, Pinterestbot | DNS |
| GPTBot, OAI-SearchBot, ChatGPT-User, DuckDuckBot | **published ranges only**: they publish no DNS records |

## Forward-confirmed reverse DNS

For a request claiming a crawler with DNS domains:

1. Reverse-resolve the client address to a hostname (PTR).
2. Check the hostname is under one of the crawler's domains.
3. Forward-resolve that hostname and check the original address is among the answers.

Step 3 is what makes it proof. Anyone can set a PTR record for their own address to
`crawl-1.googlebot.com`; nobody but Google can make `crawl-1.googlebot.com` resolve to it.

| Outcome | Result |
| --- | --- |
| verified | no detection; the request is marked as a verified crawler, exempt from `rate-spike` and `path-bruteforce` |
| refuted: hostname outside the domains, or forward lookup does not return the address | detection, score 10, **`certain`** |
| no PTR record | refuted when `treat_missing_ptr_as_forgery` (default); every listed operator publishes PTR records |
| indeterminate: a timeout or resolver failure | **nothing**. A lookup that failed proves nothing |

Answers are cached (`cachingResolver`), so a crawler making thousands of requests costs a
lookup, not thousands. Set `treat_missing_ptr_as_forgery = false` only if your resolver
cannot tell NXDOMAIN from a failure.

A confirmed crawler is exempt only from the volume detectors. Decoys, payloads and everything
else still apply: a real Googlebot fetching `/.env` from a link somebody posted is still a
fetch of `/.env`.

## Published ranges

Several operators publish the address blocks their crawlers use. Where a list exists it is
also the better check: a set lookup instead of two DNS round trips, and immune to somebody
else's DNS having a bad afternoon.

`PUBLISHED_CRAWLER_RANGES` ships the **URLs**, never the data:

| Id | Source |
| --- | --- |
| `googlebot` | `developers.google.com/…/googlebot.json` |
| `google-special` | `developers.google.com/…/special-crawlers.json` |
| `bingbot` | `www.bing.com/toolbox/bingbot.json` |
| `gptbot` | `openai.com/gptbot.json` |
| `oai-searchbot` | `openai.com/searchbot.json` |
| `chatgpt-user` | `openai.com/chatgpt-user.json` |
| `duckduckbot` | `duckduckgo.com/duckduckbot.json` |

A range baked into a release is wrong by the time somebody installs it, and wrong here means
verifying whoever has since been handed the address.

With ranges installed:

- an address **inside** a claimed crawler's list is confirmed with no DNS lookup;
- an address **outside** it is refuted (proof) **only for a crawler with no DNS records**;
  for the others DNS decides, because a list can be a refresh behind.

### The fetch is defensive

A list decides who is verified, so a list that arrived wrong would verify whatever it
covered. Each fetch:

- is HTTPS only, with a timeout and a 4 MB size cap;
- drops unparseable entries, but **refuses the whole list** if it is empty, holds more than
  10,000 prefixes, or contains a block wider than any crawler owns (`/8` for IPv4, `/19` for
  IPv6);
- on any failure keeps the previous list and reports it (`kind: "crawler-ranges-error"` in the
  service log).

### In code

```ts
import { CrawlerRanges, HoneypotEngine, crawlerVerificationDetector, startCrawlerRangeRefresh } from "@osqd/hackerpot";

const ranges = new CrawlerRanges();
const stop = startCrawlerRangeRefresh(ranges, {
  intervalMs: 12 * 3_600_000,     // floored at one hour
  onRefresh: (result) => console.info("ranges", result.updated, result.failed),
});

new HoneypotEngine({ extraDetectors: [crawlerVerificationDetector({ ranges })] });
```

| Export | |
| --- | --- |
| `CrawlerRanges` | the set; `contains(id, ip)` answers `true`, `false`, or `undefined` for a list never loaded |
| `refreshCrawlerRanges(ranges, { sources?, timeoutMs?, fetch? })` | one refresh; never throws, never partially applies; resolves to `{ updated, failed }` |
| `startCrawlerRangeRefresh(ranges, { intervalMs?, immediate?, onRefresh?, … })` | on a schedule; returns a stop function; the timer never keeps the process alive |
| `fetchCrawlerRanges(source, options)` | one list |
| `validateRanges(prefixes)` | the checks above, on your own list |

The service shares one `CrawlerRanges` across SIGHUP rebuilds, so a reload keeps the lists
fetched so far. Changing `published_ranges` or `ranges_refresh_hours` needs a restart.

## Custom resolvers and crawlers

```ts
import { cachingResolver, crawlerVerificationDetector, nodeDnsResolver, verifiableCrawlers } from "@osqd/hackerpot";

crawlerVerificationDetector({
  resolver: cachingResolver(nodeDnsResolver()),
  crawlers: [...verifiableCrawlers, { id: "mybot", name: "MyBot", tokens: ["mybot/"], domains: ["crawl.example.com"] }],
});
```

`hackerpot explain` runs this detector with a resolver that answers nothing, so a claim reads
as unverifiable rather than refuted, and the command never makes a network call.

## What it cannot tell you

**Whether a verified crawler is welcome.** Verification says who a client is, not whether you
want it; that is a policy question.

**DNS as it was.** A [replay](../testing/replay.md) verifies against today's DNS.

## Related

- [The proof guard](../concepts/the-guard.md) — why a refuted claim may block
- [The detectors](detectors.md#crawler-verification) — its options in the table
- [Configuration](../reference/configuration.md#detectors)
