# Edge bans

Banning at the firewall from the honeypot's log, with fail2ban, while the honeypot itself stays
isolated.

← [Documentation](../index.md) · [Operations](index.md)

---

A block inside hackerpot refuses an address only where hackerpot answers. In front of an
application that is the whole site, but a standalone trap sees only what your proxy sends it, so a
scanner blocked there keeps probing everything else at full speed. [Firewall
enforcement](firewall.md) pushes blocks out, but needs privileges and a way out of the honeypot's
network. The alternative on this page keeps the honeypot unprivileged and offline: **the host reads
the honeypot's log and bans from it.**

## What to ban on: verdicts

Most hits are suspicion, and a ban built on suspicion eventually lands on somebody who typed
`/.env` out of curiosity. So the service writes a separate **`verdict`** line only for hits worth
acting on at the edge, with a fixed shape:

```json
{"ts":"2026-11-25T09:41:53.191Z","kind":"verdict","ip":"203.0.113.5","reason":"burst","hits":3,"hit":"…","rule":"detector-choice","respondedWith":"decoy-content","detectors":["decoy-path"]}
```

| `reason` | When | Why it is safe to ban on |
| --- | --- | --- |
| `proof` | a detection is [proof](../concepts/the-guard.md): a replayed honeytoken, a tool naming itself, a protocol violation | no legitimate client produces it |
| `block` | the policy refused the address | the policy's own judgement; in middleware mode a block needs proof |
| `burst` | `burst_hits` hits from one address within `burst_window_ms` (default 3 within 5 s) | machine speed: a person typing bait addresses cannot do it, a script can. Reported once per window |

`kind` comes first and `ip` second, before anything the client controls, so a filter anchored at
the start of the line cannot be fooled by an `"ip":"…"` forged inside a path. In `format = "text"`
the same line reads `[ts] kind=verdict ip=203.0.113.5 reason=burst …`.

```toml
[logging]
verdicts = true          # default
burst_hits = 3
burst_window_ms = 5000
```

## fail2ban

A filter that matches any verdict, and a jail that bans on the first one:

```ini
# /etc/fail2ban/filter.d/hackerpot-verdict.conf
[Definition]
# JSON log lines (format = "json"). For format = "text", use instead:
#   failregex = ^\[[^\]]+\] kind=verdict ip=<ADDR> reason=(?:proof|block|burst)\b
failregex = ^\{"ts":"[^"]+","kind":"verdict","ip":"<ADDR>","reason":"(?:proof|block|burst)"
ignoreregex =
```

```ini
# /etc/fail2ban/jail.d/hackerpot.local
[hackerpot]
enabled   = true
filter    = hackerpot-verdict
# A container logging to journald; for a file, use logpath = /var/log/hackerpot.log
backend   = systemd
journalmatch = CONTAINER_NAME=hackerpot
maxretry  = 1
findtime  = 60
bantime   = 1h
bantime.increment = true
bantime.maxtime   = 24h
port      = http,https
# Observe first: with the dummy action nothing is banned, and fail2ban-client status
# lists who would have been. Swap in the banaction below after reviewing that list.
action    = dummy
# banaction = nftables[type=multiport, chain_hook=prerouting, chain_priority=-150]
ignoreip  = 127.0.0.1/8 ::1 <your own addresses, monitoring, VPN>
```

Check the filter against a real log before enabling the jail:

```sh
fail2ban-regex --journalmatch='CONTAINER_NAME=hackerpot' systemd-journal /etc/fail2ban/filter.d/hackerpot-verdict.conf
```

### Behind Docker, ban in `prerouting`

A port published by Docker is DNAT-ed in `PREROUTING` and forwarded through `DOCKER-USER`; it never
passes the `INPUT` chain. A ufw `deny` or fail2ban's default `input`-hook ban therefore **does not
stop** the address reaching the container. Hook the ban before Docker's DNAT (priority -100), where
the destination port is still 80 or 443:

```ini
banaction = nftables[type=multiport, chain_hook=prerouting, chain_priority=-150]
```

The parameter names belong to fail2ban's `action.d/nftables.conf`; check them against the version you
have installed. A wrong hook bans nothing, so verify with a test ban of a documentation address:

```sh
fail2ban-client set hackerpot banip 192.0.2.1
nft list ruleset | grep -A3 f2b        # the rule should sit in a prerouting chain
fail2ban-client set hackerpot unbanip 192.0.2.1
```

## Never ban shared addresses

One address can carry many unrelated people: Cloudflare and other CDN egress (WARP users among
them), Apple iCloud Private Relay, a carrier's NAT, a school. A bot behind one of them is not the
address's owner. Put those ranges in `ignoreip`: they are still recorded, scored and blocked
**inside** the honeypot, just never at the edge. Keep the list current; the providers publish
theirs.

## Make bans visible and reversible

A visitor who says "the site does not load" should be checkable in one command:

```sh
fail2ban-client status hackerpot
fail2ban-client set hackerpot unbanip <address>
```

and the ban count belongs on a dashboard. The `refused` lines and
`hackerpot_refused_blocked_total` ([metrics](metrics.md)) show what the honeypot's own blocks are
doing; fail2ban's count shows the edge's.

## Related

- [Firewall enforcement](firewall.md): the honeypot pushing blocks out itself, with privileges
- [The proof guard](../concepts/the-guard.md): what counts as proof
- [The client IP](../integration/client-ip.md): a ban is only as good as the address it acts on
