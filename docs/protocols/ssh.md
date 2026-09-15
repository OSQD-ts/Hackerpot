# SSH

Credential capture over a real handshake, and the optional fake shell.

← [Documentation](../index.md) · [Protocols](index.md)

---

SSH credential brute force is the internet's single most common automated attack.
`SshHoneypot` is a **medium-interaction** honeypot: it completes the real SSH transport
handshake, built on [`ssh2`](https://github.com/mscdex/ssh2) so the key exchange and crypto
are well tested, and captures what clients send at the authentication layer. By default it
rejects every attempt.

## Findings

| Detector id | What it catches |
| --- | --- |
| `ssh-auth-bruteforce` | password guessing: the exact **username and password** tried |
| `ssh-publickey-probe` | offered public keys: username, key algorithm, SHA256 fingerprint |
| `ssh-scan` | a connection that handshakes and takes the version banner without trying to log in |
| `ssh-shell-command` | interactive mode: one command run in the fake shell, in `body` |
| `ssh-shell-session` | interactive mode: the full ordered transcript, when the session closes |

The captured password lands in the incident's `body`, and the client's SSH version string in
`headers["ssh-client"]`, so you can see which software is knocking and which credentials are in
circulation.

## In code

```ts
import { MemoryStore, SshHoneypot } from "@osqd/hackerpot";

const store = new MemoryStore();         // share with your HoneypotServer for unified scoring
const ssh = new SshHoneypot({
  port: 2222,                            // 22 needs privileges
  ident: "OpenSSH_8.4",                  // the client sees "SSH-2.0-OpenSSH_8.4"
  store,
  onHit: (hit) => console.warn("[ssh]", hit.ip, hit.detections[0]?.detectorId),
  maxAuthAttempts: 6,
  dropAboveScore: 40,
});
await ssh.listen();                      // generates an ephemeral RSA host key if none is given
```

| Option | Default | |
| --- | --- | --- |
| `port`, `host` | —, all interfaces | |
| `ident` | `"OpenSSH_8.4"` | the server software id; the client sees `SSH-2.0-<ident>` |
| `hostKeys` | an ephemeral RSA key | host private keys, PEM or OpenSSH format |
| `maxAuthAttempts` | `6` | close the connection after this many credential attempts |
| `interactive` | `false` | accept the login and present the fake shell |
| `acceptOnAttempt` | `1` | in interactive mode, accept on this attempt; earlier ones are captured and rejected |
| `shellHostname` | `"srv01"` | hostname in the fake prompt |
| `maxCommands` | `100` | commands captured per session before it closes |
| `maxCommandLength` | `4096` | bytes kept per command |
| `store`, `onHit`, `onIncident`, `onError`, `dropAboveScore`, `maxConnections`, `maxSessionMs`, `isAllowlisted` | | see [the shared options](index.md#what-they-have-in-common) |

An ephemeral host key is all a honeypot needs: a stable identity buys nothing, and a
scanner that fingerprints host keys sees a fresh server each restart either way.

## Interactive mode

By default the honeypot captures that somebody knocked and what they tried. Interactive mode
captures what they **do** with a foothold: the URLs they `wget`, the droppers they run, their
reconnaissance sequence.

After `acceptOnAttempt` attempts it accepts the login and presents a fake shell that records
each command (`ssh-shell-command`) and, on disconnect, the transcript (`ssh-shell-session`).

**Nothing executes.** The shell is a scripted stream the honeypot writes canned output to,
shared with the Telnet honeypot (`fakeShellOutput`). There is no PTY to a real shell and no
path from a typed command to the host. It answers the recon automated attackers run in their
first ten seconds (`whoami`, `id`, `uname -a`, `cat /proc/cpuinfo`, the BusyBox applet probe)
with plausible output, and `command not found` for everything else.

`acceptOnAttempt` must not exceed `maxAuthAttempts`, or the connection closes before a shell
is ever reached; the config refuses that.

## In the standalone service

```toml
[ssh]
enabled = true
port = 2222              # 22 needs privileges
host = "0.0.0.0"
ident = "OpenSSH_8.4"
max_auth_attempts = 6
drop_above_score = 0     # 0 = never
max_connections = 256
max_session_ms = 120000  # must be > 0

interactive = false
accept_on_attempt = 1
shell_hostname = "srv01"
max_commands = 100
max_command_length = 4096

# Omit both for an ephemeral key, or pin one:
host_key_files = []      # ["/etc/hackerpot/ssh_host_rsa_key"], read at startup
host_keys = []           # inline PEM strings
```

Host key files are read when the listener is built, not when the config is validated, so
`hackerpot config` never touches private key material. If you also run the port-scan sentinel,
keep 2222 out of its port list.

To try it: `npm run demo` starts it on `:2222`, and `npm run simulate:ssh` drives a credential
spray at it. See [try it locally](../testing/try-it.md).

## Related

- [Telnet](telnet.md) — the same fake shell, a different pipe
- [Protocols overview](index.md) — shared options and the shared store
- [Data shapes](../reference/data-shapes.md) — an SSH incident
