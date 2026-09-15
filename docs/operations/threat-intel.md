# Threat intel

Consuming other honeypots' indicator feeds, without becoming an amplifier for whoever poisons one.

← [Documentation](../index.md) · [Operations](index.md)

---

The [`/ioc.txt` feed](management-api.md#rest) one hackerpot publishes, another can consume, so a
fleet shares confirmed offenders: an attacker burned on one host is already blocked on the rest.

That is powerful and, wired naively, **dangerous**. The concrete attack, rather than a vague "only
trust good feeds":

1. A peer runs `trust_proxy = true`, so it takes its client address from `X-Forwarded-For`.
2. Anyone who can reach that peer sends it a few decoy probes with a forged header naming a
   **victim address**. The peer scores the victim and lists it on `/ioc.txt`.
3. You subscribe to the peer's feed. You now block the victim.
4. Composed with [firewall enforcement](firewall.md), one poisoned honeypot makes the whole fleet
   `iptables`-block a bank, a CDN edge, or your own monitoring.

hackerpot's ingest is built so that amplifier is structurally absent in the default wiring.

## The guarantees

Each enforced in the library, where the service's poller cannot bypass it:

- **The allowlist is consulted before every ingested block, always.** There is no option to
  disable it, so a poisoned feed can never take out your own monitoring or office ranges. The
  poller reads the allowlist live, so a SIGHUP that changes it applies immediately.
- **Ingested blocks do not reach the firewall enforcer by default.** Locally observed attacks are
  first-hand evidence and earn a firewall rule; a feed is hearsay. Hearsay short-circuits requests
  here and nothing more. Escalation still works: once that address actually attacks you, a detector
  blocks it on its own merits.
- **Ingested addresses are never republished.** A blocked-at-the-door request records no hit, so it
  never appears on this honeypot's own `/ioc`, and poison cannot spread from one honeypot to the next.
- **Bounded.** Feeds must use HTTPS (plaintext only for a loopback peer), checked on every redirect
  hop; the response body is capped (2 MB by default) and times out; entries are capped per refresh;
  and every ingested block expires.

## In the standalone service

```toml
[intel]
feeds = ["https://peer-1.internal.example/ioc.txt", "https://peer-2.internal.example/ioc.txt"]
refresh_seconds = 300    # at least 30; polled with ±10% jitter
min_score = 40           # only pull confident offenders (sent as ?min_score=)
api_key = ""             # bearer token for the peer's management API
ttl_seconds = 3600       # ingested blocks expire; 0 is rejected
max_entries = 10000      # per refresh
enforce = false          # the one setting that lets a feed drive your firewall
```

Listing feeds enables it. Each refresh logs `kind: "intel"` with how many addresses were fetched,
blocked, skipped as allowlisted and skipped as invalid; a feed that is down, slow or hostile logs
`intel-error` and never takes the honeypot with it.

**`enforce = true`** writes ingested addresses to the enforcing blocklist. Enabling it logs a warning
at startup: a feed you enforce is as trusted as root on your host. Changing `enabled` or `enforce`
needs a restart, because it decides how the blocklist is composed; feeds, schedule and limits reload
on SIGHUP.

## In code

```ts
import { CompositeBlocklist, EnforcingBlocklist, HoneypotEngine, MemoryBlocklist, applyIocEntries, commandEnforcer, fetchIocFeed } from "@osqd/hackerpot";

const local = new EnforcingBlocklist(new MemoryBlocklist(), commandEnforcer({ argv: ["iptables", "-w", "-A", "INPUT", "-s", "{ip}", "-j", "DROP"] }));
const feed = new MemoryBlocklist();                               // hearsay lives here: NON-enforcing
const engine = new HoneypotEngine({ blocklist: new CompositeBlocklist(local, feed) });

// per refresh, per feed URL:
const ips = await fetchIocFeed("https://peer.example/ioc.txt?min_score=40", { apiKey, timeoutMs: 10_000 });
const result = applyIocEntries(ips, { blocklist: feed, allowlist: engine.allowlist, ttlMs: 3_600_000, maxEntries: 10_000 });
```

`CompositeBlocklist` reads across its children (`isBlocked` is true if any child blocks) and
`block()` writes **only to the first**. That is the mechanism: detections block through the engine
into the enforcing primary, while ingest writes straight into the non-enforcing `feed` child.

| Function | Options |
| --- | --- |
| `fetchIocFeed(url, options)` | `apiKey`, `timeoutMs`, `maxBytes` (2 MB), `fetch`; returns the addresses; blocks nothing |
| `applyIocEntries(ips, options)` | `blocklist` (required), `allowlist` (required), `ttlMs`, `maxEntries`, `onError`, `now`; returns `{ blocked, skippedAllowlisted, skippedInvalid, cappedAt? }` |
| `parseIps(text)` | the line parser, on its own |

Pass `onError` whenever `blocklist` is asynchronous (a `RedisBlocklist` under an explicit enforce
opt-in): a rejected block is otherwise an unhandled rejection, which terminates the process on
exactly the path you hardened.

## Only subscribe to feeds you control

Everything above makes a poisoned feed survivable. It does not make it harmless: a poisoned feed can
still waste your honeypot's attention on a victim address for `ttl_seconds`. And the peers you
subscribe to should themselves have `trust_proxy` set correctly.

## Related

- [Firewall enforcement](firewall.md) — what ingest is kept away from
- [The client IP](../integration/client-ip.md) — the setting the attack starts from
- [Management API](management-api.md) — the feed you publish
