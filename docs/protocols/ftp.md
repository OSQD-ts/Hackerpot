# FTP

Cleartext credentials, anonymous logins, traversal and the FTP bounce.

← [Documentation](../index.md) · [Protocols](index.md)

---

FTP is old, is still swept constantly (it turns up on appliances nobody administers), and
carries its credentials in the clear, which is exactly what makes a fake one pay.
`FtpHoneypot` is a **low-interaction** listener that speaks enough of RFC 959 to keep a
client working through its script.

## Findings

| Detector id | What it catches |
| --- | --- |
| `ftp-auth-bruteforce` | credential guessing through `USER` and `PASS`; captures the pair, answers `530` |
| `ftp-anonymous-login` | an `anonymous`, `ftp` or `guest` login: the oldest reconnaissance question there is |
| `ftp-bounce` | a `PORT` or `EPRT` naming an address that is **not the client's** |
| `ftp-traversal` | `../`, an encoded equivalent, a null byte or an absolute system path in any filename argument |
| `ftp-command` | interactive mode: each command issued after the login was granted |
| `ftp-scan` | a connection that takes the banner and leaves without offering a credential |

## The bounce, which is worth understanding

`PORT h1,h2,h3,h4,p1,p2` tells a real server where to open the data connection, and nothing in
the protocol says that address has to be the client's. Historically that let an attacker use
an FTP server to port-scan or attack a third party from the server's address.

hackerpot parses the command, compares the address to the peer's, reports the mismatch, and
**never opens the connection**. There is no code path from that command to a `connect()`.

**Detection does not wait for a login.** In the default configuration every post-auth command
is refused with `530`, so gating bounce and traversal findings on a successful login would
mean never reporting either. The ask is the evidence, not whether it was honoured.

No data connection is ever opened in either direction, no file is served or accepted, and there
is no filesystem behind the fake directory.

## In code

```ts
import { FtpHoneypot, MemoryStore } from "@osqd/hackerpot";

const store = new MemoryStore();
const ftp = new FtpHoneypot({
  port: 2121,                    // 21 needs privileges
  banner: "(vsFTPd 3.0.3)",
  store,
  onHit: (hit) => console.warn("[ftp]", hit.detections[0]?.detectorId, hit.path),
  dropAboveScore: 40,
});
await ftp.listen();
```

| Option | Default | |
| --- | --- | --- |
| `port`, `host` | —, all interfaces | |
| `banner` | `"(vsFTPd 3.0.3)"` | server name in the `220` greeting |
| `maxAuthAttempts` | `6` | close after this many credential attempts |
| `interactive` | `false` | accept the login (`230`) and capture the commands issued against the fake tree |
| `acceptOnAttempt` | `1` | in interactive mode, accept on this attempt |
| `maxCommands` | `100` | commands captured per session |
| `maxCommandLength` | `512` | characters kept per command |
| `store`, `onHit`, `onIncident`, `onError`, `dropAboveScore`, `maxConnections` (256), `maxSessionMs` (120000), `isAllowlisted` | | see [the shared options](index.md#what-they-have-in-common) |

Interactive mode records where a client tried to `CWD` and what it tried to `STOR`. Nothing is
created, served or deleted.

## In the standalone service

```toml
[ftp]
enabled = true
port = 2121              # 21 needs privileges
host = "0.0.0.0"
banner = "(vsFTPd 3.0.3)"
max_auth_attempts = 6
drop_above_score = 0     # 0 = never
max_connections = 256
interactive = false
accept_on_attempt = 1
max_commands = 100
max_command_length = 512
max_session_ms = 120000
```

To try it: `npm run demo` starts it on `:2121`, and `npm run simulate:ftp` drives it.

## Related

- [Protocols overview](index.md) — shared options and the shared store
- [Telnet](telnet.md) — the other cleartext credential trap
