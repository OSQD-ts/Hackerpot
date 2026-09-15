# Replaying your logs

What the configured detectors would have made of yesterday.

← [Documentation](../index.md) · [Testing](index.md)

---

Mounting a honeypot in front of an application is a claim about *your* traffic. The honest way to check
it before it tarpits anyone is to run it over traffic you already have.

```bash
npx hackerpot replay /var/log/nginx/access.log --config ./hackerpot.toml
```

```
Replayed 11 log lines: 11 parsed, 0 skipped (unrecognised format).
Flagged 9 requests (81.8%).

By detector:
  scanner-signature          9
  decoy-path                 8
  payload-injection          1

Responses it would have sent:
  tarpit                     4
  decoy-content              3
  block                      2

Blocks refused for lack of proof: 3

Top sources:
  192.0.2.44                 5 flagged of 5 requests, total score 73
  203.0.113.9                4 flagged of 4 requests, total score 59
```

Reading that: `203.0.113.9` was `sqlmap` walking decoys, which is proof, so its blocks would have gone
through. `192.0.2.44` was `curl` walking decoys; it crossed the block threshold three times without
proof, so the [guard](../concepts/the-guard.md) would have tarpitted it instead. If an address in *Top
sources* is a person, a monitor or a partner, that is the finding: you learned it from a log file rather
than from a support ticket.

It binds no port and writes to an in-memory store of its own, so a replay never touches a live one.

## How the replay behaves

**Each line is evaluated at its logged time.** An afternoon of traffic is spread the way it arrived, so the
stateful detectors see real rates rather than one enormous burst.

**Middleware rules apply.** A log comes from an application serving real users, so:

- a path counts toward `path-bruteforce` only where the log shows a **404** (or a detector flagged it);
- a block needs **proof**, and refused blocks are counted.

**Detectors that reason from a missing header stand down.** A log records a User-Agent and a Referer at
most. A header missing from a *record* is not a header missing from the *request*, so the facts are marked
`partialHeaders` and the checks for no `Host`, no `User-Agent` and a browser without `Accept` headers skip
replayed requests. Without this, a replay over ordinary nginx logs would flag every line.

A replay therefore **under-reports**: its silence is not a clean bill of health. Body detectors see no
bodies, and header detectors see only what the log kept.

## Formats

Detected per line.

**Combined or common log format:**

```
203.0.113.9 - - [15/Sep/2026:09:01:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "sqlmap/1.7.2#stable"
```

**One JSON object per line**, with any of these field names:

| Field | Accepted names |
| --- | --- |
| address | `ip`, `remote_addr`, `client_ip`, `remoteAddress` (required) |
| method | `method`, `request_method` (required) |
| target | `url`, `uri`, `request_uri`, `path`, `target` (required) |
| time | `timestamp`, `time`, `ts`, `@timestamp` (ISO string or epoch ms; now if absent) |
| status | `status`, `status_code` |
| User-Agent | `user_agent`, `userAgent`, `http_user_agent` |
| Referer | `referer`, `referrer`, `http_referer` |
| headers | `headers`: an object of name → value |

```json
{ "ip": "203.0.113.5", "method": "GET", "url": "/products/12?ref=mail", "status": 200, "time": "2026-09-15T09:00:00Z", "headers": { "user-agent": "Mozilla/5.0 …", "accept-language": "en-GB" } }
```

**JSON Lines is better.** Configure your access log to emit the headers you care about, and the replay sees
more of what detection would have seen. Lines in neither format are counted as skipped.

## `--json`

```json
{
  "lines": 11,
  "parsed": 11,
  "skipped": 0,
  "flagged": 9,
  "byDetector": { "scanner-signature": 9, "decoy-path": 8, "payload-injection": 1 },
  "byResponse": { "tarpit": 4, "decoy-content": 3, "block": 2 },
  "downgraded": 3,
  "topSources": [{ "ip": "192.0.2.44", "requests": 5, "flagged": 5, "totalScore": 73 }]
}
```

## In code

```ts
import { HoneypotEngine, MemoryStore, formatReplaySummary, parseLogLine, readLogLines, replayLog } from "@osqd/hackerpot";

const engine = new HoneypotEngine({ store: new MemoryStore(), enricher: null });   // an engine of its own
const summary = await replayLog(engine, readLogLines("access.log"), {
  onFlagged: (request, result) => console.log(request.ip, request.target, result.detections.map((d) => d.detectorId)),
});
console.log(formatReplaySummary(summary));
```

`parseLogLine(line)` returns `{ ip, method, target, timestamp, status?, headers }`, or `undefined`.
`onFlagged` is the way to read the flagged requests one at a time, which is the useful part.

## What it cannot tell you

**Bodies.** No access log keeps them, so injection in a POST body never shows.

**DNS as it was.** `crawler-verification` checks against today's DNS.

**The effect of the response.** A replay shows what would have been sent, not how the traffic would have
adapted to being tarpitted.

## Related

- [The command line](cli.md) — `replay` beside the other commands
- [Shadow mode](../detection/shadow-mode.md) — the same question, against live traffic with headers and bodies
- [The corpus](corpus.md) — traffic you do not have yet
