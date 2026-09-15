# The client IP

`trust_proxy` and `X-Forwarded-For`: the highest-consequence setting, and the easiest to get wrong.

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
trust_proxy = false      # the default
```

```ts
new HoneypotEngine({ trustProxy: false });
```

| `trust_proxy` | The address is |
| --- | --- |
| `false` (default) | the socket's remote address. `X-Forwarded-For` is ignored entirely |
| `true` | the **leftmost** entry of `X-Forwarded-For`, if it parses as an IP address; otherwise the socket address |

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

Enable `trust_proxy` **only** when every request reaches the listener through a proxy you control, and
that proxy **overwrites** `X-Forwarded-For` rather than appending to it.

hackerpot reads the **leftmost** entry. A proxy that appends leaves the leftmost entry exactly as the
client wrote it, so it is attacker-controlled. Configure the proxy to replace the header:

```nginx
proxy_set_header X-Forwarded-For $remote_addr;    # overwrite: the leftmost entry is the real client
# NOT: proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;   # appends
```

And make sure the listener is not reachable **around** the proxy. If the honeypot's port is published
directly as well, anyone who finds it sends their own header. The compose file sets
`TRUST_PROXY=false` for exactly this reason: it publishes `4004` straight to the host.

Behind several proxies (a CDN in front of nginx), the proxy nearest the honeypot must write the address
it received from the one before, which is usually a CDN-specific header (`CF-Connecting-IP`,
`True-Client-IP`) mapped into `X-Forwarded-For`.

## Validation

A forwarded value must parse as an IPv4 or IPv6 address (`net.isIP`). A bracketed IPv6 literal
(`[2001:db8::1]`) is unwrapped first. Anything else (`unknown`, a hostname, garbage) is ignored and the
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
