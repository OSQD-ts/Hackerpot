# Protocol honeypots

The TCP listeners beside the HTTP honeypot, and the store they share.

← [Documentation](../index.md)

---

The most common automated attacks on the internet are not HTTP. SSH and Telnet credential
sprays, SMTP relay abuse, anonymous FTP logins and port sweeps arrive on every public address
all day. hackerpot ships a listener for each, speaking just enough of the protocol to keep a
client talking and recording what only abuse produces.

| Listener | Interaction | Captures | Page |
| --- | --- | --- | --- |
| `SshHoneypot` | medium: a real SSH handshake; optional fake shell | usernames, passwords, offered keys, commands | [SSH](ssh.md) |
| `SmtpHoneypot` | low | AUTH attempts, relay attempts, spam bodies, VRFY and EXPN probes | [SMTP](smtp.md) |
| `FtpHoneypot` | low; optional command capture | cleartext credentials, anonymous logins, traversal, bounce attempts | [FTP](ftp.md) |
| `TelnetHoneypot` | medium: option negotiation; optional fake shell | the default-credential list being sprayed, dropper commands | [Telnet](telnet.md) |
| `PortScanSentinel` | none | connections to decoy ports, sweeps | [Port scans](port-scan.md) |

## What they have in common

**Nothing is ever authenticated for real, relayed, served or executed.** The interactive
shells are scripted streams with no path to a process. No FTP data connection is opened in
either direction. No mail leaves.

**One store, one score.** Each listener maps its incidents into the same `HoneypotHit` shape
as HTTP hits, with `method` set to `"SSH"`, `"SMTP"`, `"FTP"` or `"TELNET"`, and records them
into the store you give it. Share the HTTP engine's store and an address brute-forcing SSH
raises the same score that gets it blocked on HTTP. The management API and the dashboard show
every protocol side by side.

```ts
import { FtpHoneypot, HoneypotServer, MemoryStore, SmtpHoneypot, SshHoneypot, TelnetHoneypot } from "@osqd/hackerpot";

const store = new MemoryStore();
const http = new HoneypotServer({ store });
const onHit = (hit) => http.engine.publish(hit);          // so dashboard subscribers see every protocol

await http.listen(4004);
await new SshHoneypot({ port: 2222, store, onHit }).listen();
await new SmtpHoneypot({ port: 2525, store, onHit }).listen();
await new FtpHoneypot({ port: 2121, store, onHit }).listen();
await new TelnetHoneypot({ port: 2323, store, onHit }).listen();
```

**Options every listener takes:**

| Option | Default | |
| --- | --- | --- |
| `port` | — | required |
| `host` | all interfaces | bind address |
| `store` | — | share it for unified scoring; needed for `dropAboveScore` |
| `onHit` | — | each incident as a `HoneypotHit` |
| `onIncident` | — | the protocol-native incident, with session detail |
| `onError` | — | failures the listener absorbs |
| `dropAboveScore` | off | refuse connections from addresses at or above this cumulative score |
| `maxConnections` | 256 | simultaneous connections |
| `maxSessionMs` | 120000 | hard lifetime of one connection |
| `isAllowlisted` | — | a predicate; an allowlisted source is never recorded or reported |

**Bounded by construction.** They are fed at a rate the attacker chooses, so every listener
caps connections, session lifetime, authentication attempts, captured commands and their
length. `maxSessionMs` exists because an idle timeout is reset by every byte: a client
dripping one character every 20 seconds would otherwise hold its slot forever. The config
refuses `0`.

**The allowlist applies.** `isAllowlisted` is a predicate rather than an `IpAllowlist` so a
SIGHUP that reloads the allowlist is honoured live, since these listeners are not rebuilt on
reload. Before it existed, an allowlisted monitor that touched a protocol honeypot was
scored, stored and published on `/ioc.txt`, where peer honeypots would ingest and block it.

## In the standalone service

Each is a config section, **off by default**: binding a service port is a deliberate choice,
and the privileged ports (21, 22, 23, 25) need capabilities the container does not have. The
defaults are the usual unprivileged stand-ins; map the real port to them at the edge if you
want real traffic.

| Section | Default port |
| --- | --- |
| `[ssh]` | 2222 |
| `[smtp]` | 2525 |
| `[ftp]` | 2121 |
| `[telnet]` | 2323 |
| `[port-scan]` | none; listing ports enables it |

The service wires each to the shared store, the log, the management API, syslog and the
in-process dashboard. Two listeners on one port is a startup error naming both sections.
Changing any of these sections needs a restart.

**What you store changes.** Captured passwords, commands and mail bodies are
attacker-controlled text that lands in your logs, your store and every webhook you forward
to. Length is capped, the text log escapes control characters so a capture cannot forge a log
line, and webhooks and the dashboard redact credentials by default. A captured mail body may
carry live malware or somebody else's personal data, which you then hold.

## Related

- [How it works](../concepts/how-it-works.md) — the HTTP side
- [Actors](../concepts/actors.md) — one score across protocols
- [Docker](../integration/docker.md) — publishing these ports from a container
