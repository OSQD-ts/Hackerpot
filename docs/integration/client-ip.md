# The client IP

`trust_proxy`, `trusted_proxies` and `X-Forwarded-For`: the highest-consequence setting, and the easiest to get wrong.

← [Documentation](../index.md) · [Integration](index.md)

---

## Why it matters more than anything else

The resolved client address is what everything keys on:

- the **allowlist** exempts it;
- the **score** accumulates against it;
- the **blocklist** blocks it, and the **firewall enforcer** drops it;
- the **IOC feed** publishes it, and peers ingest it;
- the stateful detectors count its activity.

Get it wrong in one direction and attackers choose their own address. Get it wrong in the other and every
visitor shares one. Neither failure errors, and neither logs.

## The setting

```toml
[server]
trust_proxy = false                         # the default
# trust_proxy = true
# trusted_proxies = ["10.0.0.0/8"]          # the proxies you run: recommended
# proxy_hops = 1                            # or: how many there are, when you cannot list them
# forwarded_header = "x-forwarded-for"
```

```ts
new HoneypotEngine({ proxy: { trustProxy: true, trustedProxies: ["10.0.0.0/8"] } });
// `trustProxy: true` on its own is still accepted, as `proxy: { trustProxy: true }`.
```

| Setting | The address is |
| --- | --- |
| `trust_proxy = false` (default) | the socket's remote address. The forwarded header is ignored entirely |
| `trust_proxy = true` + `trusted_proxies` | only when the **connecting peer is one of `trusted_proxies`**: the chain is walked **from the right**, skipping your own proxies, and the first address that is not one of them is the client. From any other peer the header is ignored and the socket address is used |
| `trust_proxy = true` without `trusted_proxies` | the `proxy_hops`-th entry **from the right** (default 1: the address your proxy appended). A chain shorter than that uses the socket address |

The model is adapted from bothandlerjs, so the two libraries resolve the same request to the same address.

## Wrongly on: attackers pick their address

`X-Forwarded-For` is a client-supplied header. With `trust_proxy = true` and nothing overwriting it, any
client can:

- **escape its score** by sending a new address with every request;
- **impersonate an allowlisted source**, `X-Forwarded-For: 10.0.0.5`, and bypass detection entirely;
- **frame someone else**: probe with a victim's address until it is blocked, published on `/ioc.txt`,
  ingested by every peer, and firewalled.

That is why the default is off, and must stay that way: defaulting on made every directly exposed
deployment vulnerable unless the operator knew to turn it off.

## Wrongly off: everyone is the proxy

Behind nginx, a load balancer or a CDN with `trust_proxy = false`, every request arrives from the proxy's
address. Nothing looks broken: hits are recorded and the dashboard fills up. But:

- every attacker shares **one score**, so per-address scoring means nothing;
- `/ioc.txt` exports the proxy's address;
- once that shared score crosses the block threshold, **the honeypot blocks the proxy**: a 403 for every
  request from everyone, first probe included.

## Getting it right

Enable `trust_proxy` **only** when requests reach the listener through proxies you control, and list them
in `trusted_proxies`. That is the variant that cannot be talked round:

- a request from a peer that is **not** in `trusted_proxies` never has its header read, so the port being
  reachable around the proxy (published directly, reachable inside the network) no longer lets anyone
  choose their own address;
- the chain is read **from the right**, where your proxies append, so a client that prepends entries
  (`X-Forwarded-For: 10.0.0.5` to impersonate an allowlisted source) only adds entries nobody reads;
- an extra hop appearing later (a CDN in front of nginx) is skipped as long as its addresses are listed.

Without `trusted_proxies`, `proxy_hops` must match the topology exactly: the Nth address from the right is
taken, so one proxy fewer than configured hands the choice to the client, and the header is still read
from any peer. Prefer listing the proxies.

Either way nginx may append (`$proxy_add_x_forwarded_for`) or overwrite (`$remote_addr`): the rightmost
entry is the one it wrote.

An earlier version took the **leftmost** entry and read the header from any peer. The leftmost entry is
the one the client writes, so that configuration was only safe behind a proxy that overwrote the header
on a listener nobody could reach directly.

## Validation

Every entry in the chain must parse as an IPv4 or IPv6 address (`net.isIP`). A port is removed first
(`203.0.113.9:51234`, `[2001:db8::1]:443`), and a bracketed IPv6 literal is unwrapped. Anything else (`unknown`, a hostname, garbage) is ignored and the
socket address is used. Without this, any header value became the "address", which let an attacker mint
unlimited distinct keys for every per-address map, or collide every source into one bucket.

The firewall enforcer validates again before running anything, so a hostile header can never reach a
command line.

## Addresses are compared by value

The allowlist compares parsed addresses, not strings: `::ffff:10.1.2.3` matches `10.0.0.0/8`, and
`2001:db8::1`, `2001:0DB8:0:0:0:0:0:1` and `2001:db8::0:1` are one entry. An entry that cannot be matched
at runtime is a startup error rather than a range that silently exempts nothing.

**Do not allowlist loopback in production** if a proxy or sidecar on the same host fronts the honeypot:
with `trust_proxy = false` every request in the world arrives from `127.0.0.1`.

## On a Fetch runtime

There is no socket. Pass the address the platform gives you:

```ts
const handle = withFetchHoneypot(engine, app.fetch);
await handle(request, { ip: platformClientAddress });
```

Without `ip`, every request shares one empty address, unless `trustProxy` is on, in which case
`X-Forwarded-For` is read as above.

## Checking it

Look at the address on a hit you caused yourself from a known address. If it is the proxy's, turn
`trust_proxy` on. If you can change it by sending `X-Forwarded-For: 192.0.2.1`, something in front is
appending, or the listener is reachable directly.

A private or loopback address on an internet-facing honeypot's incidents is itself a signal: the
[enrichment](../concepts/how-it-works.md#enrichment) marks it, and it usually means one of the two.

## Related

- [nginx edge capture](nginx.md) — the edge that needs `trust_proxy = true`
- [Firewall enforcement](../operations/firewall.md) — what a spoofed address could reach
- [Threat intel](../operations/threat-intel.md) — how a spoofed address spreads
