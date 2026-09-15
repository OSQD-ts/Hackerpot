# SMTP

AUTH brute force, open relay, spam and mailbox enumeration, on a mail server that never sends mail.

← [Documentation](../index.md) · [Protocols](index.md)

---

`SmtpHoneypot` is a **low-interaction** mail listener. It speaks enough of the protocol
(`EHLO`, `AUTH`, `MAIL FROM`, `RCPT TO`, `DATA`, `VRFY`, `EXPN`…) to look usable and keep a
client talking, and recognises the four things that only ever come from abuse.

**Nothing is ever authenticated or relayed.**

## Findings

| Detector id | What it catches |
| --- | --- |
| `smtp-auth-bruteforce` | credential guessing through `AUTH LOGIN` or `PLAIN`; captures the pair, always answers `535` |
| `smtp-open-relay` | an external `MAIL FROM` to an external `RCPT TO`: trying to relay spam through you |
| `smtp-spam` | a message actually delivered over `DATA`: the spam or phishing payload, captured, never sent |
| `smtp-user-enumeration` | `VRFY` or `EXPN` probing for which mailboxes exist |

The `DATA` message is captured, with the parsed `Subject` in `headers["smtp-subject"]` and the
size in `headers["smtp-message-bytes"]` for quick triage.

## In code

```ts
import { MemoryStore, SmtpHoneypot } from "@osqd/hackerpot";

const store = new MemoryStore();
const smtp = new SmtpHoneypot({
  port: 2525,                    // 25 needs privileges
  banner: "Postfix",
  hostname: "mail",
  localDomains: ["mycorp.test"], // mail for anything else, from an external sender, is relay abuse
  store,
  onHit: (hit) => console.warn("[smtp]", hit.detections[0]?.detectorId, hit.path),
  dropAboveScore: 40,
});
await smtp.listen();
```

| Option | Default | |
| --- | --- | --- |
| `port`, `host` | —, all interfaces | |
| `banner` | `"Postfix"` | server name in the `220` greeting and `EHLO` reply |
| `hostname` | `"mail"` | hostname in `EHLO` and `HELO` responses |
| `localDomains` | `[]` | domains this server would legitimately accept mail for; empty accepts nothing as local |
| `captureBody` | `true` | store the raw `DATA` body |
| `maxBodyChars` | `2000` | characters of body kept when captured |
| `store`, `onHit`, `onIncident`, `onError`, `dropAboveScore`, `maxConnections`, `maxSessionMs`, `isAllowlisted` | | see [the shared options](index.md#what-they-have-in-common) |

## Whether to keep the body

The body is the payload itself: a phishing lure, a malware attachment, sometimes somebody
else's personal data. Keeping it is useful for classifying a campaign, and it is also content
you now hold and must handle.

`captureBody: false` stops storing it while still recording the parsed `Subject` and the byte
count, which is usually enough to triage. The config refuses `max_body_chars = 0` with
`capture_body = true`: say you do not want bodies rather than capturing empty ones.

## In the standalone service

```toml
[smtp]
enabled = true
port = 2525                       # 25 needs privileges
host = "0.0.0.0"
banner = "Postfix"
hostname = "mail"
local_domains = ["mycorp.test"]   # lowercased at parse time
drop_above_score = 0              # 0 = never
max_connections = 256
max_session_ms = 120000
capture_body = true
max_body_chars = 2000
```

To try it: `npm run demo` starts it on `:2525`, and `npm run simulate:smtp` drives relay,
enumeration and brute-force attempts at it.

## Related

- [Protocols overview](index.md) — shared options and the shared store
- [Webhooks](../operations/webhooks.md) — `omit_body` before alerting on spam captures
