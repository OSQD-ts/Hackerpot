# Runtime changes

SIGHUP reload, `reconfigure()`, and what needs a restart.

← [Documentation](../index.md) · [Operations](index.md)

---

## SIGHUP

Send the standalone service `SIGHUP` and it re-reads its config file, applies what can be applied
safely, and names everything else.

```bash
kill -HUP "$(pidof node)"
docker kill --signal=HUP hackerpot
```

```json
{"ts":"…","kind":"reload-requires-restart","key":"server","reason":"the HTTP listener is already bound","note":"not applied; restart to change this"}
{"ts":"…","kind":"reload","config":"/app/hackerpot.toml","applied":["detectors","policy"],"requiresRestart":["server"],"detectors":23}
```

Three rules:

1. **A file that fails validation changes nothing.** It is logged as `reload-failed` and the running
   configuration is kept, so a bad edit cannot take the honeypot down.
2. **A setting that cannot be applied is named**, with the reason, before the rest is applied. An
   operator who edited a port, reloaded and saw no error would otherwise believe it took. Silently
   ignoring a changed setting is the failure this is designed around.
3. **A reload with no changes says so** (`note: "no changes"`).

Environment variables are re-read with the file, and still win.

## What reloads, and what does not

| Applied live | |
| --- | --- |
| `[detectors.*]` | the whole detector set is rebuilt, with fetched crawler ranges kept |
| `[engine] shadow_detectors` | promote or demote a shadowed detector |
| `[responses.*]` | the action registry is rebuilt |
| `[policy]` | thresholds |
| `[allowlist]` | read live by the protocol listeners and the intel poller too |
| `[service_tokens]` | |
| `[logging]` | format, and `include_headers` / `include_body`, together |
| `[intel]` feeds, schedule, `min_score`, `api_key`, TTL, cap | the poller is replaced |

| Needs a restart | Why |
| --- | --- |
| `[server]` | the HTTP listener is already bound |
| `[store.*]` | swapping the store would discard accrued scores |
| `[blocklist]` | swapping the blocklist would drop active blocks |
| `[engine] activity_window_ms` | the sliding windows hold live per-address history |
| `[engine] fingerprint_window_ms` | the actor registry holds live history |
| `[engine] detector_timeout_ms` | the engine reads it once when built |
| `[port-scan]`, `[smtp]`, `[ssh]`, `[ftp]`, `[telnet]` | the listeners are already bound |
| `[syslog]` | the transport is opened at startup |
| `[management]` | the listener is already bound |
| `[dashboard]` | the listener is already bound |
| `[intel] enabled`, `enforce` | they decide how the blocklist is composed |
| `[audit]` | its windows and timer are built at startup |
| `[detectors.crawler-verification] published_ranges`, `ranges_refresh_hours` | the refresher is started at startup |

The deciding principle: anything that holds **live state an attacker has accrued** (scores, blocks,
windows) or a **bound socket** is not rebuilt, because rebuilding it would hand every attacker a clean
slate or drop live connections.

`planReload(running, next)` is the pure function behind this, and it is exported: it returns
`{ applied, requiresRestart, unchanged }` without applying anything.

## In code: `reconfigure()`

```ts
engine.reconfigure({
  detectors: buildDetectors(nextConfig),
  responseActions: buildResponseActions(nextConfig),
  policy: buildPolicy(nextConfig),
  allowlist: ["127.0.0.1", "10.0.0.0/8", "192.0.2.0/24"],
  shadowDetectors: ["target-integrity"],
  serviceTokens: { tokens: { "uptime-monitor": process.env.MONITOR_TOKEN! } },
});
```

Only the fields you pass are replaced, and they take effect on the next request. The engine reads
detectors, actions, policy, allowlist, shadow set and service tokens live on every request, so nothing
has to be rebuilt around it.

`store`, `blocklist` and the activity windows are **not** accepted, for the reasons above. A reload
path of your own should refuse a change to those loudly rather than ignore it; `planReload` does
the diff.

Listeners built around an engine should read the allowlist through the engine
(`engine.isAllowlisted(ip)`) rather than capture an `IpAllowlist`, which would keep exempting
yesterday's set after a reload. The protocol honeypots take an `isAllowlisted` predicate for exactly
this reason.

## Related

- [Configuration](../reference/configuration.md) — every key
- [Shadow mode](../detection/shadow-mode.md) — the usual reason to reload
- [Stores](stores.md) — why the store is fixed
