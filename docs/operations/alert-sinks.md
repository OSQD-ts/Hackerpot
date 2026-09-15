# Alert sinks

Slack, Discord, and syslog or CEF for a SIEM: every field assumed hostile, because every field is.

← [Documentation](../index.md) · [Operations](index.md)

---

An incident feed is only useful if it reaches somebody. Three destinations ship, and all three
assume every field they carry is attacker-written: the request path, the User-Agent, a captured
shell command, and the detector `reason` strings that quote them back.

## Slack and Discord

Point a [webhook](webhooks.md) at the platform's own incoming-webhook URL and set `format`:

```toml
[[management.webhooks]]
url = "https://hooks.slack.com/services/T000/B000/xxxx"
format = "slack"          # or "discord"; default "hackerpot" is the native JSON
min_score = 20
dedupe_window_seconds = 300
```

This reuses the whole delivery path (signing, retries, dedupe, throttling, the in-flight cap)
and changes only the body. What the rendering adds is the escaping each platform needs:

| Risk | What the renderer does |
| --- | --- |
| `GET /@everyone` pages your whole Discord server | text is markdown-escaped, **and** the payload carries `allowed_mentions: {parse: []}`, the platform's own guarantee that no mention resolves |
| `<!channel>` in a path pings a Slack channel | Slack builds mentions from angle brackets, so `&`, `<` and `>` are escaped |
| a URL in a captured path is **fetched** by your chat provider, telling the attacker the probe landed | link previews are off on both (`unfurl_links`/`unfurl_media` false; Discord's `SUPPRESS_EMBEDS`) |
| a newline in a captured value forges an extra field in the alert | every value is flattened to one line first |
| a huge capture exceeds the message limit | fields and the whole message are truncated to fit |

`omit_body` **defaults to `true`** for these formats. The request body is raw attacker payload
(a serialized exploit, a malware stager, sometimes somebody else's data) and a chat client
renders it to everyone in the channel. Set `omit_body = false` if you genuinely want it.

Anomalies and suppression summaries are rendered for the platform too.

> Escaping is not a promise that alert text is attacker-*free*. Detector `reason` strings quote
> slices of the request by design. Render alerts as plain text wherever they land.

In code: `renderAlert(format, incident, { omitBody })`, `renderAnomaly(format, anomaly)`,
`escapeSlack(text)`, `escapeDiscord(text)`.

## Syslog and SIEM

```toml
[syslog]
host = "siem.internal"    # setting a host turns it on
port = 514
protocol = "udp"          # or "tcp": reconnects with backoff and reports what it lost
format = "cef"            # "cef" | "json" | "text"
facility = 13             # 0–23; 13 is log audit
severity = 4              # 0–7; 4 is warning
hostname = "hackerpot"
min_score = 0
max_bytes = 1024          # at least 480
include_body = false
```

This is **deliberately independent of `[management]`**: shipping to a SIEM should not also
require exposing a REST API over your captured attacker data. It sits directly on the hit path,
so it forwards HTTP and protocol-honeypot incidents alike.

| Format | Inside the syslog envelope |
| --- | --- |
| `cef` | ArcSight Common Event Format: what Splunk, QRadar, ArcSight and Elastic parse natively |
| `json` | the same fields the JSON log emits |
| `text` | the key=value line the text log emits |

### Three properties the transport holds

All because it is fed at a rate the attacker chooses:

1. **One message is always one line.** Syslog is line-framed, so a newline inside a captured
   value would end the record and let what follows be read as a separate event, with a source
   address of the attacker's choosing, indistinguishable from a real detection. The formatters
   escape; the transport strips again anyway.
2. **Messages are bounded.** RFC 3164 only obliges a receiver to accept 1024 bytes, and a UDP
   datagram past the path MTU is silently lost, so a long capture is truncated rather than sent
   into a hole. Truncation never splits a UTF-8 character. The body is off by default because it
   is what blows past `max_bytes`.
3. **Drop, never queue.** When a TCP collector is down, or connected but not reading, messages
   are discarded and the loss is reported **once**, not once per message. A queue in front of an
   unavailable consumer is unbounded memory growth moved somewhere less visible.

### In code

```ts
import { SyslogSink } from "@osqd/hackerpot";

const sink = new SyslogSink({ host: "siem.internal", protocol: "tcp", minScore: 20 });
sink.start();                          // open the TCP connection now, not on the first hit
sink.attach(management.broker);        // or call sink.send(hit) from your own onHit
```

| Option | Default |
| --- | --- |
| `host` | required |
| `port` | `514` |
| `protocol` | `"udp"` |
| `format` | `"cef"` |
| `facility`, `severity` | `13`, `4` |
| `hostname` | `"hackerpot"` |
| `minScore` | `0` |
| `maxBytes` | `1024` |
| `maxQueuedBytes` | `1048576`: TCP bytes allowed unflushed before messages are dropped |
| `includeBody` | `false` |
| `onError` | — |

**Call `start()` for TCP.** Without it the connection is opened by the first `send()`, which is
then dropped for want of a ready socket, so the first thing an attacker does becomes the one
event that never reaches the SIEM. The service calls it before any listener binds, which also
surfaces an unreachable collector at startup instead of mid-attack. It is a no-op for UDP.

`send(hit)` never throws and never returns a promise: it sits on the hit path, where a rejection
would be an unhandled rejection an attacker triggers by probing.

### Formatting without the sink

```ts
import { cefFormat, syslogLine } from "@osqd/hackerpot";

new HoneypotServer({
  onHit: (hit) => {
    console.log(cefFormat(hit));
    // CEF:0|hackerpot|hackerpot|0.1.0|nosql-injection|NoSQL operator injection|9|src=203.0.113.7 requestMethod=POST request=/login …
    udpSocket.send(syslogLine(hit, { host: "sensor1" }), 514, "siem.internal");
    // <108>Aug 27 12:34:56 sensor1 hackerpot: CEF:0|hackerpot|…
  },
});
```

`syslogLine(hit, { host?, facility?, severity?, message? })` wraps the CEF line by default; pass
`message` to ship something else. Both escape line structure and control characters in every
field. `formatTextLine(event)` renders the same injection-safe key=value line the service logs.

## Related

- [Webhooks](webhooks.md) — the delivery path Slack and Discord ride on
- [Threat model](../concepts/threat-model.md#injection-into-logs-alerts-and-metrics)
