# Webhooks

Signed pushes, retries, deduplication, throttles and redaction.

← [Documentation](../index.md) · [Operations](index.md)

---

Each configured URL receives an HTTP `POST` per incident. Webhooks are delivered by the
management server, so they need `[management]` enabled.

```toml
# Every incident at or above a score, signed, to your own receiver:
[[management.webhooks]]
url = "https://hooks.example.com/hackerpot"
secret = "shared-signing-secret"
min_score = 20
max_retries = 3
[management.webhooks.headers]
X-Team = "security"

# A danger alert to a channel somebody watches: a high bar, deduplicated, throttled:
[[management.webhooks]]
url = "https://hooks.slack.com/services/T000/B000/xxxx"
format = "slack"
min_score = 40
dedupe_window_seconds = 300
throttle_window_seconds = 3600
max_per_window = 20
```

## Options

| Key | Default | |
| --- | --- | --- |
| `url` | — | required; http or https |
| `format` | `"hackerpot"` | `"hackerpot"` posts the native JSON; `"slack"` and `"discord"` render a readable, escaped message. See [alert sinks](alert-sinks.md) |
| `secret` | — | sign each delivery with HMAC-SHA256 |
| `headers` | — | extra static headers, such as a token the receiver expects |
| `min_score` | `0` | only incidents whose cumulative score is at least this |
| `max_retries` | `3` | attempts before giving up |
| `timeout_ms` | `10000` | per attempt; must be > 0 |
| `max_in_flight` | `32` | concurrent deliveries for this hook; past it, deliveries are dropped and reported |
| `dedupe_window_seconds` | off | suppress repeats from the same address inside the window |
| `throttle_window_seconds` + `max_per_window` | off | at most N deliveries per window; **both** are required, and setting one is a startup error |
| `omit_body` | `false` for `hackerpot`, `true` for `slack` and `discord` | strip the attacker-controlled request body |
| `redact` | `true` | strip credentials from the delivered copy |
| `anomalies` | `true` | also deliver [traffic anomalies](audit.md) |

And one across every hook:

```toml
[management]
webhook_global_max_per_minute = 120   # 0 = unlimited
```

## The payload

```json
{ "type": "incident", "incident": { "id": "…", "ip": "203.0.113.7", "path": "/.env", "detections": [ … ], "totalScore": 10, "respondedWith": "decoy-content" } }
```

Anomalies, unless the hook sets `anomalies = false`:

```json
{ "type": "anomaly", "anomaly": { "id": "probe-campaign", "severity": "warning", "summary": "…", "value": 14, "baseline": 0, "timestamp": "…" } }
```

When dedupe, throttling or a cap holds anything back, one summary at the end of the window:

```json
{ "type": "suppressed", "count": 12, "windowSeconds": 60 }
```

Silence is ambiguous: somebody watching a quiet channel cannot tell "nothing happened" from "a
lot happened and was held back". The summary removes the ambiguity. Full shapes are in
[data shapes](../reference/data-shapes.md#webhook-payloads).

## Verifying a delivery

With a `secret`, every attempt is signed afresh, two ways:

| Header | Covers | |
| --- | --- | --- |
| `X-Hackerpot-Signature: sha256=<hex>` | the body alone | kept for existing receivers; a captured delivery can be replayed indefinitely |
| `X-Hackerpot-Signature-V2: sha256=<hex>` | `<timestamp>.<body>` | with `X-Hackerpot-Timestamp` (Unix seconds); reject old timestamps and a captured delivery is useless |

Verify V2, and reject timestamps more than a few minutes old:

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

function verify(rawBody: string, headers: Record<string, string | undefined>, secret: string): boolean {
  const timestamp = Number(headers["x-hackerpot-timestamp"]);
  const signature = headers["x-hackerpot-signature-v2"] ?? "";
  if (!Number.isFinite(timestamp) || Math.abs(Date.now() / 1000 - timestamp) > 300) return false;
  const expected = `sha256=${createHmac("sha256", secret).update(`${timestamp}.${rawBody}`).digest("hex")}`;
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
```

Verify the **raw** body, before any JSON parser re-serialises it.

## Delivery

- **Retries** back off exponentially, up to `max_retries`.
- **Refusals are not retried.** A 4xx other than 408, 425 or 429 fails the same way every time,
  so it is reported at once instead of holding an in-flight slot through the backoff.
- **Drop, never queue.** Past `max_in_flight`, the throttle or the global cap, a delivery is
  dropped and reported. Deliveries are attacker-driven, one incident one POST, and a queue in
  front of a slow receiver is unbounded growth moved somewhere less visible.
- **Anomalies** bypass `min_score`, dedupe and the per-hook throttle, which are about incidents;
  the audit's cooldown keeps them rare. The global and in-flight caps still apply.

## Turning a firehose into an alert

A webhook with a high `min_score` *is* an alert channel: it fires only when an address crosses
into confirmed-attacker territory. For one somebody watches:

- **`dedupe_window_seconds`** makes one noisy attacker one alert, not hundreds.
- **`throttle_window_seconds` + `max_per_window`** caps the channel; beyond it incidents are
  dropped, not queued, so a flood cannot page you into the ground.
- **`omit_body`** keeps raw attacker payload out of a client that renders content. It strips the
  body only: detection `reason` strings and captured headers still quote attacker input, so
  render alert text as plain text, never markup.

## Redaction

On by default. The copy delivered to the hook, and only that copy, has:

- `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `X-Auth-Token`
  replaced with `[redacted]`, keeping the header name so it is visible one was sent;
- any header whose name reads as a secret (`secret`, `token`, `api-key`, `passw`,
  `credential`) likewise;
- secret-named fields in a form-encoded or JSON body likewise;
- every removed value scrubbed from detection reasons and metadata, because detectors quote what
  they saw.

A body that is neither form-encoded nor valid JSON is sent unchanged. Detection and the store
keep everything. Set `redact = false` only for a receiver you control that needs the captured
credentials themselves. `redactIncident(incident)` is exported for your own sinks.

## In code

`WebhookConfig` is the camelCase of the table above, passed as `webhooks` to
`ManagementServer`. `WebhookDispatcher` is exported for delivering without the management server.

## Related

- [Alert sinks](alert-sinks.md) — Slack, Discord and syslog
- [Firewall enforcement](firewall.md) — the other webhook: one per block
- [Data shapes](../reference/data-shapes.md) — every payload
