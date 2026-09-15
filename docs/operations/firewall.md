# Firewall enforcement

Pushing blocks out to iptables, nftables, fail2ban or a WAF, so a confirmed attacker is dropped before reaching the process.

← [Documentation](../index.md) · [Operations](index.md)

---

By default a block lives inside hackerpot: a request from a blocked address is answered `403`
before any detector runs, which is cheap but still costs a connection. Enforcement pushes each block
**out**, to the operating system's firewall or your own automation.

It is off by default, and worth reading this page before turning it on.

## The risk, first

Enforcement acts on the **resolved** client address. With `trust_proxy = true` that is whatever
`X-Forwarded-For` said. If anything untrusted can reach the honeypot directly, an attacker can forge
that header and make you firewall-block an arbitrary victim: a denial of service you inflict on
someone else, on request.

Enable enforcement only with a trusted proxy in front and `trust_proxy` set correctly, or with
`trust_proxy = false`. See [the client IP](../integration/client-ip.md).

## In the standalone service

```toml
[blocklist]
backend = "memory"            # or "redis", sharing [store.redis]'s connection
max_entries = 100000

[blocklist.enforcer]
command = "iptables"
args = ["-w", "-A", "INPUT", "-s", "{ip}", "-j", "DROP"]
timeout_ms = 5000
# max_per_window = 50         # default 50/s for a command, 100/s for a webhook
# window_ms = 1000
```

Other commands:

```toml
# nftables
command = "nft"
args = ["add", "element", "inet", "filter", "blocked", "{ ip }"]

# fail2ban
command = "fail2ban-client"
args = ["set", "hackerpot", "banip", "{ip}"]
```

Or a webhook to a small privileged helper:

```toml
[blocklist.enforcer]
webhook = "https://waf.internal.example/block"
secret = "shared-signing-secret"
[blocklist.enforcer.headers]
X-Team = "security"
```

Setting `command` or `webhook` enables it; one or the other, not both. The config refuses a command
whose `args` has no `{ip}` token, since the same command for every block could not target the
address.

## Safe by construction

- **No shell.** `args` is a real array, run through `execFile`, so no pipeline or metacharacter is
  ever interpreted.
- **Only a validated address is substituted.** The address is checked with `net.isIP` centrally,
  before any enforcer runs, so a forged `--flush` or `1.2.3.4; curl evil` is refused rather than
  passed to the command.
- **A spawn-rate ceiling.** With `trust_proxy` on, one host can mint unlimited distinct addresses
  through `X-Forwarded-For`, each crossing the block threshold in a few requests and each otherwise
  spawning a firewall process: a fork bomb, no botnet needed. Past `max_per_window`, external
  enforcement is **dropped, not queued**. The in-process block still holds, so the honeypot stays
  protected; only the firewall rule is skipped, and the drop is logged.
- **Errors are reported, never thrown.** A failing firewall call cannot break the honeypot's own
  response; it is logged as `kind: "enforce-error"`.
- **Every block is caught.** Enforcement wraps the blocklist, and all blocking flows through the
  blocklist, so blocks from any source are enforced, not only those from the `block` action.
- **Ingested feed entries are not enforced**, unless `[intel] enforce = true`. See
  [threat intel](threat-intel.md).

## The webhook payload

```json
{ "type": "block", "ip": "203.0.113.7", "blockedUntil": "2026-09-15T10:17:00.000Z" }
```

With `secret`, the body is HMAC-SHA256 signed in `X-Hackerpot-Signature: sha256=<hex>`, as
management webhooks are. The URL is yours and this process will call it, so point it somewhere you
trust.

## Command or webhook?

The `block` response awaits the enforcer, so each blocked request waits up to `timeout_ms` and, for a
command, spawns a process. Under a flood of distinct addresses prefer the **webhook**: a small
privileged helper does the dropping, and the honeypot does not need `CAP_NET_ADMIN`. Running the
internet-facing process with the privileges to rewrite the host firewall is exactly what the compose
file's `cap_drop: [ALL]` is there to avoid.

## In code

```ts
import { EnforcingBlocklist, HoneypotEngine, MemoryBlocklist, commandEnforcer, webhookEnforcer } from "@osqd/hackerpot";

new HoneypotEngine({
  trustProxy: true,        // only behind a proxy that overwrites X-Forwarded-For
  blocklist: new EnforcingBlocklist(
    new MemoryBlocklist(),
    commandEnforcer({ argv: ["iptables", "-w", "-A", "INPUT", "-s", "{ip}", "-j", "DROP"], maxPerWindow: 50 }),
    (error) => console.error("[firewall]", error.message),
  ),
});
```

| Factory | Options |
| --- | --- |
| `commandEnforcer` | `argv` (required, with `{ip}`), `timeoutMs`, `maxPerWindow` (50), `windowMs`, `onError` |
| `webhookEnforcer` | `url` (required), `secret`, `headers`, `timeoutMs` (10000), `maxPerWindow` (100), `windowMs`, `onError` |

A `BlockEnforcer` is just `(ip, blockedUntilEpochMs) => void | Promise<void>`, so anything else (a
cloud WAF API, a queue) is a function.

## The blocklists

| Class | |
| --- | --- |
| `MemoryBlocklist({ maxEntries })` | the default: per instance, lost on restart. Bounded (100,000): expired entries are swept first, then the soonest-to-expire live blocks are shed. Losing a block is graceful; the address is re-detected on its next request |
| `RedisBlocklist({ client, keyPrefix })` | blocks survive restarts and apply across every replica; each block is a key with a native TTL |
| `CompositeBlocklist(primary, ...others)` | reads across all, writes to the primary |
| `EnforcingBlocklist(inner, enforcer, onError?)` | every block also fires the enforcer |

Changing `[blocklist]` needs a restart: swapping the blocklist would drop active blocks.

## Related

- [Response actions](../responses/actions.md#block) — the `block` action's own options
- [Threat intel](threat-intel.md) — keeping hearsay away from the firewall
- [The client IP](../integration/client-ip.md) — read before enabling
