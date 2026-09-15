# Data shapes

Incidents, API responses, webhook payloads, and live-feed messages.

← [Documentation](../index.md)

---

Every shape here is attacker-influenced somewhere: paths, headers, bodies, reasons that quote them.
Render them as text, never as markup.

## The incident

An **incident** is a `HoneypotHit`. It is exactly what the store holds, `GET /incidents/:id` returns, the
WebSocket and webhooks push, and `onHit` receives.

```jsonc
{
  "id": "86610780-8cbe-449d-aa2d-f2602b5b2f53",   // UUID
  "timestamp": "2026-09-15T09:47:16.859Z",        // ISO 8601
  "ip": "203.0.113.7",                             // the resolved client address
  "method": "GET",                                 // or "SSH", "SMTP", "FTP", "TELNET"
  "path": "/.env",                                 // normalised
  "headers": { "host": "example.com", "user-agent": "curl/8.5.0" },
  "body": "…",                                     // when one was read; capped at 64 KB
  "fingerprint": "a3f9c21e0b7d",                   // the actor fingerprint
  "enrichment": { "category": "documentation", "global": false },
  "detections": [                                  // highest score first
    {
      "detectorId": "decoy-path",
      "reason": "Exposed .env file probe",
      "score": 10,
      "metadata": { "decoyId": "dotenv", "payload": { "status": 200, "contentType": "text/plain; charset=utf-8" } }
    },
    {
      "detectorId": "scanner-signature",
      "reason": "User-Agent matches known tooling signature: curl/8.5.0",
      "score": 6,
      "metadata": { "userAgent": "curl/8.5.0", "pattern": "python-requests|go-http-client|libwww-perl|curl\\/|wget\\/" }
    }
  ],
  "score": 16,                                     // points this request added
  "totalScore": 16,                                // the address's cumulative score after it
  "respondedWith": "decoy-content"                 // the response action that ran

  // Present only when they apply:
  //   "rawPath"           the target as sent, when it differs from path ("//.env", "/%2eenv")
  //   "shadowDetections"  findings from shadowed detectors, which added no score
  //   "downgradedFrom"    "block", when the proof guard refused a block
}
```

### A detection

```ts
{
  detectorId: string;
  reason: string;
  score: number;
  respondWith?: string;
  certain?: boolean;      // proof
  family?: string;        // e.g. "path-traversal"
  metadata?: Record<string, unknown>;
}
```

### Protocol incidents

The protocol honeypots map their findings into the same shape. The finding is the `detectorId`
(`ssh-auth-bruteforce`, `smtp-open-relay`, `ftp-bounce`, `telnet-command`…), `method` names the
protocol, and captures ride in `path`, `body` and `headers`:

| Honeypot | Notable fields |
| --- | --- |
| SSH | `body`: the password or the command; `headers["ssh-client"]`: the client version; `headers["ssh-user"]` |
| SMTP | `headers["smtp-subject"]`, `headers["smtp-message-bytes"]`; `body`: the message when captured |
| FTP, Telnet | `body`: the credential or command |

`onIncident` on each honeypot receives the protocol-native `SshIncident`, `SmtpIncident`, `FtpIncident` or
`TelnetIncident` instead, with session detail.

## Management API responses

### `GET /incidents`, `GET /incidents/:id`

```json
{ "incidents": [ { "id": "…", "…": "…" } ] }
{ "incident": { "id": "…", "…": "…" } }
```

### `GET /stats`

```json
{
  "totalIncidents": 42,
  "uniqueIps": 10,
  "byDetector": { "decoy-path": 5, "rate-spike": 10, "payload-injection": 5 },
  "byResponse": { "not-found": 12, "tarpit": 22, "block": 4, "decoy-content": 4 },
  "topOffenders": [ { "ip": "203.0.113.11", "score": 40, "incidents": 5 } ],
  "firstSeen": "2026-09-15T09:47:16.859Z",
  "lastSeen": "2026-09-15T10:02:21.531Z"
}
```

### `GET /ioc`, `GET /ioc.txt`

```json
{ "indicators": [ { "ip": "203.0.113.11", "score": 40, "incidents": 5, "detectors": ["decoy-path", "scanner-signature"], "firstSeen": "…", "lastSeen": "…" } ] }
```

```
203.0.113.11
198.51.100.23
```

### `GET /sessions`, `GET /sessions/:ip`

```json
{
  "session": {
    "ip": "203.0.113.11",
    "score": 40,
    "incidents": 5,
    "detectors": ["decoy-path", "payload-injection"],
    "responses": ["decoy-content", "tarpit", "block"],
    "firstSeen": "…",
    "lastSeen": "…",
    "timeline": [
      { "timestamp": "…", "method": "GET", "path": "/.env", "detectors": ["decoy-path"], "score": 10, "totalScore": 10, "respondedWith": "decoy-content" }
    ]
  }
}
```

`/sessions` answers `{ "sessions": [...] }`.

### `GET /actors`, `GET /actors/:fingerprint`

```json
{ "actor": { "fingerprint": "a3f9c21e0b7d", "ips": ["203.0.113.11", "198.51.100.23", "192.0.2.9"], "score": 71, "incidents": 12, "detectors": ["…"], "firstSeen": "…", "lastSeen": "…" } }
```

`/actors` answers `{ "actors": [...] }`, most addresses first.

### Errors

```json
{ "error": "unauthorized" }                    // 401, with WWW-Authenticate: Bearer
{ "error": "too many failed authentications" } // 429
{ "error": "not found" }                       // 404
```

## The WebSocket live feed

`GET /stream` on the management API:

```json
{ "type": "connected", "ts": "2026-09-15T10:00:00.000Z" }
{ "type": "incident", "incident": { "…": "…" } }
{ "type": "lagged", "dropped": 12 }
```

## The dashboard's event stream

The dashboard's own server-sent events at `/api/events` (behind its authentication), which a remote
dashboard source feeds from the WebSocket above:

```
retry: 3000

event: hello
data: {"version":"0.1.0","source":"this process"}

id: 1
event: incident
data: { …incident, redacted as the dashboard is configured… }

event: lagged
data: {"dropped":4}

event: skipped
data: {"skipped":37}
```

`lagged` means this viewer stopped reading; `skipped` means incidents past `maxEventsPerSecond` were
counted and not sent. The dashboard's JSON endpoints (`/api/bootstrap`, `/api/incidents`, `/api/stats`,
`/api/sessions`, `/api/actors`, `/api/ioc`, `/api/metrics`) answer in the management API's shapes, with
redaction and masking applied. See [the dashboard](../operations/dashboard.md).

## Webhook payloads

With `format = "hackerpot"`:

```json
{ "type": "incident", "incident": { "…": "…" } }
```

```json
{ "type": "anomaly", "anomaly": { "id": "probe-campaign", "severity": "warning", "metric": "distinct sources probing a new path", "value": 14, "baseline": 0, "summary": "14 different addresses started probing \"/api/v2/debug\" in the last 3 minute(s), a path nothing probed before. This is what a newly published exploit looks like.", "timestamp": "…", "details": { "path": "/api/v2/debug" } } }
```

```json
{ "type": "suppressed", "count": 12, "windowSeconds": 60 }
```

Headers on every delivery with a `secret`: `X-Hackerpot-Signature`, `X-Hackerpot-Signature-V2`,
`X-Hackerpot-Timestamp`. The incident is redacted unless `redact = false`, and has no `body` with
`omit_body`. See [webhooks](../operations/webhooks.md).

With `format = "slack"`, a Slack incoming-webhook body (`text`, with `unfurl_links` and `unfurl_media`
false). With `format = "discord"`, a Discord body (`content`, `allowed_mentions: { parse: [] }`, the
suppress-embeds flag). See [alert sinks](../operations/alert-sinks.md).

### The firewall enforcer webhook

```json
{ "type": "block", "ip": "203.0.113.7", "blockedUntil": "2026-09-15T10:17:00.000Z" }
```

## A traffic anomaly

```ts
{
  id: string;             // "flagged-share-spike", "traffic-spike", "block-spike", "downgrade-spike", "detector-failures", "probe-campaign"
  severity: "info" | "warning" | "critical";
  summary: string;
  metric: string;
  value: number;
  baseline: number;
  ratio?: number;         // absent when the baseline was zero
  timestamp: string;
  details?: Record<string, unknown>;
}
```

## The service log

One JSON object per line on stdout (with `[logging] format = "json"`). A hit:

```json
{"ts":"2026-09-15T10:00:00.000Z","kind":"hit","id":"…","ip":"203.0.113.7","method":"GET","path":"/.env","score":10,"totalScore":10,"respondedWith":"decoy-content","detectors":["decoy-path"],"reasons":["Exposed .env file probe"]}
```

`headers` and `body` are added with `include_headers` and `include_body`. Every other kind is listed in
[operations](../operations/index.md#the-service-log).

## `hackerpot explain --json`

```json
{
  "request": { "method": "GET", "path": "/.env", "query": {}, "headers": { "user-agent": "sqlmap/1.7.2#stable" }, "ip": "203.0.113.10" },
  "detections": [ { "detectorId": "decoy-path", "…": "…" }, { "detectorId": "scanner-signature", "certain": true, "…": "…" } ],
  "score": 16,
  "totalScore": 16,
  "actionId": "decoy-content",
  "fingerprint": "…",
  "path": "/.env",
  "shadowDetections": []
}
```

`hackerpot replay --json` is on [the replay page](../testing/replay.md#--json).

## Related

- [How it works](../concepts/how-it-works.md#what-a-hit-records) — what each incident field means
- [Management API](../operations/management-api.md) · [Webhooks](../operations/webhooks.md)
