# Service tokens

Letting your own monitors through when their address cannot be allowlisted.

← [Documentation](../index.md) · [Integration](index.md)

---

An uptime monitor is a bare HTTP client: no browser headers, a scripting User-Agent, the same path every
minute. In middleware mode that is exactly what `scanner-signature`, `client-anomaly` and `rate-spike`
look for. The [allowlist](client-ip.md#addresses-are-compared-by-value) solves it when the monitor has a
fixed address, which hosted monitors do not.

A service token solves it without the address. A request presenting a valid token in
`x-hackerpot-token` is **exempt like an allowlisted address**: no block check, no detection, no activity
window, no audit, and **no record anywhere**.

```toml
[service_tokens]
header = "x-hackerpot-token"

[service_tokens.tokens]
uptime-monitor = "a-long-random-string-from-a-real-source"
ci-smoke-test = "another-long-random-string"
```

```ts
new HoneypotEngine({ serviceTokens: { tokens: { "uptime-monitor": process.env.MONITOR_TOKEN! } } });
```

The monitor sends:

```
GET /healthz HTTP/1.1
x-hackerpot-token: a-long-random-string-from-a-real-source
```

## What it buys over writing the check yourself

Handed no help, the check people write compares a header with `===`, which leaks the secret a character
at a time to anyone who can time it, and prints the header in full wherever a request is logged.

- **Constant-time comparison.** Both values are hashed and the digests compared, so a length mismatch is
  not an oracle for the secret's length either. Every configured token is compared even after a match, so
  the time taken does not reveal which one matched.
- **Only names travel.** The startup log lists token names; the secrets appear nowhere. An exempt request
  is never recorded, so its header never reaches a store, a webhook or the dashboard.
- **Weak secrets are reported.** A secret shorter than 16 characters (`MIN_SERVICE_TOKEN_LENGTH`) logs a
  `warning` at startup naming the token. It is not refused, so a rotation can still start.
- **Empty secrets are refused.** An empty value (an unset environment variable interpolated into the
  file) is a startup error, since it would match nothing.

## Limits

A shared secret in a header does not expire and is replayable by anyone who sees it once. It suits a
monitor you operate calling an endpoint you operate, not anything a third party holds. Serve it over TLS,
rotate it, and give each monitor its own.

It exempts a request from the honeypot only. It grants nothing in your application.

## Details

| Option | TOML | Default |
| --- | --- | --- |
| `header` | `header` | `"x-hackerpot-token"`; letters, digits and hyphens |
| `tokens` | `[service_tokens.tokens]` | none: name → secret |

`[service_tokens]` reloads on SIGHUP, and `engine.reconfigure({ serviceTokens })` swaps them in code.
`ServiceTokens` is exported: `new ServiceTokens(options).identify(headers)` returns the matching name, and
`.weak` lists names with short secrets. `EvaluationResult.serviceToken` names the token that exempted a
request.

## Related

- [The client IP](client-ip.md) — the allowlist, for fixed addresses
- [Adapters](adapters.md) — every front end honours tokens
