# Telnet

The IoT botnet sweep, option negotiation handled properly, and what droppers run once they think they are in.

← [Documentation](../index.md) · [Protocols](index.md)

---

`TelnetHoneypot` is the highest-yield trap in this project, for an unglamorous reason. Telnet
has no transport security, so credentials arrive in the clear, and the IoT botnet families
descended from Mirai sweep ports 23 and 2323 continuously with a hard-coded list of vendor
defaults. What you collect is **the live default-credential list being sprayed at your
netblock**, and, in interactive mode, the staging URL the dropper reaches for the moment it
believes it is in.

## Findings

| Detector id | What it catches |
| --- | --- |
| `telnet-auth-bruteforce` | a `login:` and `Password:` pair, captured in the clear |
| `telnet-command` | interactive mode: each command run in the fake shell |
| `telnet-session` | interactive mode: the full ordered transcript, when the session closes |
| `telnet-scan` | a connection that takes the banner and leaves without submitting a password |

Each failed login **re-prompts**, exactly as `telnetd` does, so a botnet working through its
list hands over the whole list rather than one pair.

## Option negotiation is handled, not skipped

Telnet interleaves control commands with data: an `IAC` byte (`0xFF`) starts a two- or
three-byte command, or a variable-length sub-negotiation. A honeypot that reads the stream as
plain text ends up with `0xFF` sequences embedded in the credentials it captured.
`TelnetCodec` (exported, and tested on its own) strips and answers them, holding two
properties that matter under hostile input:

- **Resumable across chunks.** An attacker can send one byte at a time; the parser state
  survives between reads, so a split command is still one command.
- **Bounded replies.** Negotiation is symmetric, and a hostile peer can answer each refusal
  with another request forever. Past a cap the honeypot stops replying and keeps reading. A
  honeypot that can be made to generate unbounded traffic is an amplifier.

Because the honeypot announces `WILL ECHO`, it controls the echo, which is what lets it echo
the username keystroke by keystroke and **withhold the password**, like a real login.

## Nothing executes

The fake shell is a scripted stream shared with the [SSH honeypot](ssh.md#interactive-mode)
(`fakeShellOutput` in `src/shell.ts`). The same botnets run the same recon down either pipe,
so one implementation means one place to make the illusion better. It answers the BusyBox
applet probe (`/bin/busybox <APPLET>` → `applet not found`) that IoT droppers use to
fingerprint a live device, and it fetches nothing for a `wget` or `curl`: the URL has already
been captured, which is the entire value.

## In code

```ts
import { MemoryStore, TelnetHoneypot } from "@osqd/hackerpot";

const store = new MemoryStore();
const telnet = new TelnetHoneypot({
  port: 2323,                    // 23 needs privileges; 2323 is itself heavily swept
  banner: "Ubuntu 22.04.3 LTS",
  hostname: "srv01",
  interactive: true,
  store,
  onHit: (hit) => console.warn("[telnet]", hit.detections[0]?.detectorId, hit.body),
});
await telnet.listen();
```

| Option | Default | |
| --- | --- | --- |
| `port`, `host` | —, all interfaces | |
| `banner` | the fake MOTD (`FAKE_MOTD`) in code; `"Ubuntu 22.04.3 LTS"` in the config | printed before the login prompt; a device-shaped one draws the sweeps |
| `hostname` | `"srv01"` | in the `login:` and shell prompts |
| `maxAuthAttempts` | `3` | what `telnetd` allows; each failure re-prompts |
| `interactive` | `false` | accept the login and present the fake shell |
| `acceptOnAttempt` | `1` | in interactive mode, accept on this attempt |
| `maxCommands` | `100` | commands captured per session |
| `maxCommandLength` | `4096` | characters kept per line |
| `store`, `onHit`, `onIncident`, `onError`, `dropAboveScore`, `maxConnections` (256), `maxSessionMs` (120000), `isAllowlisted` | | see [the shared options](index.md#what-they-have-in-common) |

## In the standalone service

```toml
[telnet]
enabled = true
port = 2323              # 23 needs privileges
host = "0.0.0.0"
banner = "Ubuntu 22.04.3 LTS"
hostname = "srv01"
max_auth_attempts = 3
drop_above_score = 0
max_connections = 256
interactive = false      # the post-login capture is the reason to run this
accept_on_attempt = 1
max_commands = 100
max_command_length = 4096
max_session_ms = 120000
```

Captured commands are attacker-controlled text landing in your logs, store and webhooks. Length
is capped, and the text log escapes control characters so a captured command cannot forge log
lines.

To try it: `npm run demo` starts it on `:2323`, and `npm run simulate:telnet` replays a
Mirai-style default-credential sweep followed by the BusyBox fingerprint and a payload fetch.

## Related

- [SSH](ssh.md) — the same shell over a real handshake
- [Protocols overview](index.md) — shared options and the shared store
