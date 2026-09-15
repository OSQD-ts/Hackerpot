# Security

## Reporting a vulnerability

Email **platosz.michal@gmail.com** with `[hackerpot]` in the subject. Please do not open a
public issue for anything exploitable. Include a reproduction if you can; you will get an
acknowledgement within a few days.

Supported versions: the latest published release of `@osqd/hackerpot` and the
`ghcr.io/osqd-ts/hackerpot` image built from it.

---

## What hackerpot is, in security terms

A **deception and detection layer**: decoys that attract automated attacks, detectors that
recognise them, and responses that waste the attacker's time. It is not a security
boundary. It does not replace authentication, authorisation, input validation, patching or
a WAF, and nothing protected by those should depend on it. An attacker who avoids every
decoy should find nothing behind them that the decoys were protecting.

It runs in two positions, and they carry different risks:

- **Standalone**, on its own address or ports, where everything that reaches it is
  unsolicited. The main risk is to the honeypot host itself.
- **Middleware**, in front of a real application, where it sees real users. The main risk
  is harming them: blocking a person, slowing a page, or taking the application down.

---

## Threat model

### Defended against

| Threat | How |
| ------ | --- |
| **Blocking a real visitor on accumulated suspicion** | In middleware mode a block needs proof (`blockRequiresProof`): a replayed honeytoken, a hidden trap, a protocol violation no client stack emits, a self-declared attack tool, or a refuted crawler claim. Without proof the request is tarpitted and nothing is blocklisted. Refusals are counted (`hackerpot_downgrades_total`) and a spike in them is reported by the audit. |
| **The honeypot taking the host application down** | Middleware fails open: an error inside the honeypot is reported and the request continues to your routes. Every detector, store call, enricher, webhook and alert sink is failure-isolated; asynchronous detectors run under a deadline. |
| **Path spelling used to evade decoys and rules** | Paths are decoded exactly once, backslashes normalised, duplicate slashes collapsed and dot segments resolved before any detector matches; the raw form is kept for detectors that care how a target was written. Prefix decoys match only at a `/` or `.` boundary. |
| **Allowlist bypass by address spelling** | Addresses are compared by value, so IPv4-mapped IPv6, compressed and expanded IPv6 and letter case all match the same entry. |
| **Address spoofing through `X-Forwarded-For`** | Ignored unless `trust_proxy` is on, and a forwarded value must parse as an IP address. Enable it only behind a proxy that overwrites the header. |
| **Crawler impersonation** | Forward-confirmed reverse DNS and operator-published address ranges. A refuted claim is proof; a DNS timeout proves nothing. Published range lists are fetched over HTTPS only, capped in size, and refused whole if they contain a block wider than any crawler owns. |
| **Memory exhaustion** | Every structure keyed by client input (per-IP activity, fingerprints, port-scan state, auth failures, webhook dedupe, audit campaign paths) has a hard ceiling. Query parameters past 256 are not inspected, and a request that sends more is flagged. |
| **CPU exhaustion through detection** | Regex signatures are linear and matched against bounded input; values with none of the characters a payload needs skip the payload patterns entirely. `npm run bench:guard` holds the request path to budgets in CI. |
| **Alerting used as an amplifier** | Webhooks deduplicate per IP, throttle per hook, cap deliveries globally and in flight, and send a summary of what they held back. Audit anomalies have a per-check cooldown. |
| **Injection into logs, alerts and metrics** | Captured values are escaped for each sink: text log lines, Slack and Discord messages (mentions neutered, link previews off), syslog and CEF, Prometheus label values. |
| **Leaking captured credentials** | Webhook payloads are redacted by default: credential headers, secret-named headers and body fields, and those values wherever detectors quoted them. Service-token secrets are compared in constant time and never logged. |
| **Management API exposure** | Bound to loopback by default, every endpoint except `/health` needs an API key, failed authentication is rate-limited per peer, and the dashboard refuses to bind beyond loopback without authentication, checks the `Host` header against DNS rebinding, throttles wrong credentials, and never sends the management key to a browser. |
| **A poisoned threat-intel feed** | Feeds must use HTTPS, are size- and entry-capped, never override the allowlist, expire, and by default cannot reach the firewall enforcer. |
| **Command injection through firewall enforcement** | The enforcer runs an argv array without a shell, and substitutes only a validated IP address. |

### Out of scope

- **An attacker who avoids the decoys.** Detection is of automated probing and known attack
  shapes. A careful human who requests only real pages and sends no payload is not what
  this finds.
- **Distributed low-and-slow traffic.** One request per address per hour from a large pool
  defeats every per-address signal by construction; the audit's campaign check sees some of
  it in aggregate, and nothing more.
- **Signature accuracy over time.** Scanner User-Agents, exploit paths and crawler ranges
  describe populations that change. Keep the package updated, and trial retuned detectors
  in shadow mode before they act.
- **Retaliation.** Response actions waste an attacker's time and resources on connections
  they opened; nothing here reaches out to an attacker's infrastructure.
- **The host it runs on.** Isolate a standalone honeypot from anything valuable; the
  interactive SSH, FTP and Telnet shells are scripted and execute nothing, but the listeners
  are internet-facing code.
