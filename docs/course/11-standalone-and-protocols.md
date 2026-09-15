# Lesson 11 — The standalone service and protocol honeypots

**Goal:** run Pantry's honeypot as a service from a configuration file, validate that file
before it binds anything, and put an SSH listener beside it that shares one score.

← [Course](index.md) · Prev: [In front of an app](10-in-front-of-an-app.md) · Next: [Operating it](12-operating-it.md)

---

## Two positions

| Position | What reaches it | Reads bodies | Blocks | Main risk |
| --- | --- | --- | --- | --- |
| **Middleware** (lesson 10) | every request Pantry serves | only for flagged requests | with proof | harming real users |
| **Standalone** (this lesson) | only unsolicited traffic | always | on score | the honeypot host itself |

Standalone, the honeypot runs on an address or ports nothing links to. There is no
application behind it, so it reads every body up front, answers anything it did not flag
with a 404, and blocks on score, because nothing legitimate should be arriving.

They combine. A common shape is nginx diverting obvious probes to a standalone honeypot,
the middleware inside Pantry catching the rest, and both writing one store.

## Do this

`pantry/hackerpot.toml`:

```toml
# Pantry's honeypot, on its own address.
[server]
port = 14004

[detectors.decoy-path]
disabled = ["admin-panel", "swagger"]

[detectors.honeytoken]
tokens = [{ value = "AKIA_PANTRY_7Q2XK4", label = "decoy-env-aws-key" }]

[detectors.trap]
enabled = true
paths = ["/internal/export.csv"]
form_fields = ["website"]

[ssh]
enabled = true
port = 12222

[management]
port = 19500
api_keys = ["pantry-management-key-0123456789"]
```

Every port is moved off its default (4004, 2222, 9500), so nothing in this lesson collides
with anything you already run. The file is found automatically: `./hackerpot.toml` is the
first place the command looks.

Everything in it is what you did in code in lessons 6 and 7. Every key not written keeps
its default, and the shipped `hackerpot.toml` in the package is exactly those defaults,
annotated.

## Validate it before it binds anything

```bash
npx hackerpot config | head -12
```

### Checkpoint

```
{
  "source": "…/pantry/hackerpot.toml",
  "server": {
    "host": "0.0.0.0",
    "port": 14004,
    "trustProxy": false
  },
  "logging": {
    "format": "json",
    "startup": true,
    "includeHeaders": false,
    "includeBody": false
```

The `source` is the absolute path to your file. `config` resolves the file with environment
overrides applied, validates it, and prints it with every credential redacted — safe to run
in CI and over a screen share.

```bash
npx hackerpot detectors | tail -4
```

```
repeat-actor               headers         One actor fingerprint seen attacking from several distinct IPs (IP rotation)
honeytoken                 body            A seeded honeytoken (fake credential/key/id) was replayed in a request

25 detectors installed from …/pantry/hackerpot.toml.
```

Twenty-five: the default twenty-three, plus `trap` and `honeytoken`.

```bash
npx hackerpot check
```

```
ok     decoy-content (200)
ok     not-found (404)
ok     redirect (302)
ok     block (403)
held   tarpit
held   drip-feed (200)
ok     large-payload (200)
ok     fake-success (200)
ok     fake-data (200)
ok     gzip-bomb (200)
ok     chaos (200)
ok     rate-limit (429)

all 12 response actions answered
```

A config can validate and still produce a response that breaks once a request is routed to
it. `check` serves every enabled action once over loopback with a throwaway blocklist.
`held` means still delaying or streaming when it stopped waiting, which is the job of
`tarpit` and `drip-feed`. `chaos` answers a random status or random bytes on purpose, so its
number will differ on your run; a deliberate 5xx is not a failure. `check` exits 1 if any
action failed.

## Run it

```bash
npx hackerpot serve
```

It logs one JSON object per event to stdout. The first is the startup line:

```
{"ts":"2026-09-15T17:06:14.490Z","kind":"startup","config":"…/pantry/hackerpot.toml","listen":"0.0.0.0:14004","store":"memory(max 10000)","blocklist":"memory(max 100000)","allowlist":0,"detectors":["trap","decoy-path","payload-injection","ssrf-probe","nosql-injection","prototype-pollution","insecure-deserialization","graphql-abuse","jwt-weakness","crlf-injection","web-shell","header-anomaly","header-integrity","target-integrity","host-header-injection","sensitive-file","open-redirect","suspicious-method","credential-bruteforce","path-bruteforce","scanner-signature","client-anomaly","rate-spike","repeat-actor","honeytoken"],"shadow":[],"serviceTokens":[],"audit":"every 60s","crawlerRanges":"off","responses":["decoy-content","not-found","redirect","block","tarpit","drip-feed","large-payload","fake-success","fake-data","gzip-bomb","chaos","rate-limit"],"policy":{"blockThreshold":40,"tarpitThreshold":15},"honeytokens":1,"scanPorts":[],"smtp":"off","ssh":"0.0.0.0:12222","ftp":"off","telnet":"off","syslog":"off","management":"127.0.0.1:19500","dashboard":"off","intel":"off","trustProxy":false,"reload":"SIGHUP"}
```

Read it once, properly. It names every listener, the store, every detector, the policy and
what is off. "It started" is not the same as "it started the way I meant", and this line is
where the difference shows.

In a second terminal:

```bash
curl -s -o /dev/null -w "GET /.env (sqlmap) %{http_code}\n" -A "sqlmap/1.7.2#stable" http://127.0.0.1:14004/.env
curl -s -o /dev/null -w "GET /recipes (browser) %{http_code}\n" -A "Mozilla/5.0 Chrome/126" http://127.0.0.1:14004/recipes
node -e 'const s=require("net").connect(12222,"127.0.0.1");s.once("data",d=>{console.log("ssh banner:",String(d).trim());s.destroy()})'
curl -s -H "Authorization: Bearer pantry-management-key-0123456789" http://127.0.0.1:19500/stats
```

### Checkpoint

```
GET /.env (sqlmap) 200
GET /recipes (browser) 404
ssh banner: SSH-2.0-OpenSSH_8.4
{"totalIncidents":1,"uniqueIps":1,"byDetector":{"decoy-path":1,"scanner-signature":1},"byResponse":{"decoy-content":1},"topOffenders":[{"ip":"127.0.0.1","score":16,"incidents":1}],"firstSeen":"2026-09-15T17:06:14.507Z","lastSeen":"2026-09-15T17:06:14.507Z"}
```

Timestamps will differ. And in the first terminal, one line for the probe:

```
{"ts":"2026-09-15T17:06:14.511Z","kind":"hit","id":"ed968d1f-96b3-40a0-89c0-21e3aa51b1a3","ip":"127.0.0.1","method":"GET","path":"/.env","score":16,"totalScore":16,"respondedWith":"decoy-content","detectors":["decoy-path","scanner-signature"],"reasons":["Exposed .env file probe","User-Agent matches known tooling signature: sqlmap/1.7.2#stable"]}
```

The `id` is random. Stop it with Ctrl-C, or `SIGTERM`; it logs `"kind":"shutdown"` and every
listener closes.

The browser's request for `/recipes` got a 404 and left no incident: standalone, there is
nothing behind the honeypot to hand it to.

## The protocol honeypots

The most common automated attacks on the internet are not HTTP: SSH and Telnet credential
sprays, SMTP relay abuse, anonymous FTP logins, port sweeps. The service ships a listener
for each, speaking just enough of the protocol to keep a client talking.

| Section | Default port | Captures |
| --- | --- | --- |
| `[ssh]` | 2222 | usernames, passwords, offered keys, commands in an optional fake shell |
| `[smtp]` | 2525 | AUTH attempts, relay attempts, spam, VRFY and EXPN probes |
| `[ftp]` | 2121 | cleartext credentials, anonymous logins, traversal, bounce attempts |
| `[telnet]` | 2323 | the default-credential list being sprayed, dropper commands |
| `[port-scan]` | none | connections to decoy ports, sweeps |

Three things they share. **Nothing is ever authenticated for real, relayed, served or
executed** — the shells are scripted streams with no path to a process. **They are off by
default**, because binding a service port is a deliberate choice. And **they share the HTTP
honeypot's store**, so an address brute-forcing SSH raises the same score that gets it
blocked on HTTP.

The privileged ports (21, 22, 23, 25) need capabilities the container does not have. Map the
real port to the unprivileged one at the edge: `22:2222`.

## Exercise

Break the file two ways and see what `check` and `config` say: give `[server] port` a string
value, and misspell `admin-panel` in the decoy list. What exit code does each produce, and
why does the second matter more than it looks?

<details>
<summary>Checkpoint</summary>

```bash
printf '[server]\nport = "four thousand"\n' > bad.toml
npx hackerpot check --config bad.toml; echo "exit $?"
printf '[detectors.decoy-path]\ndisabled = ["admin-pannel"]\n' > typo.toml
npx hackerpot config --config typo.toml; echo "exit $?"
```

```
hackerpot: …/pantry/bad.toml: [server.port] must be a number, got string ("four thousand")
exit 2
hackerpot: …/pantry/typo.toml: [detectors.decoy-path.disabled] names built-in decoys that do not exist: admin-pannel
exit 2
```

Exit code **2** means "an operator mistake in the config", distinct from 1 for a failing
action or a runtime failure, so a CI step can tell them apart.

The typo is the one that matters. Accepted silently, it would leave the `admin-panel` decoy
**on** — and Pantry's real admin panel serving a fake login page to every administrator.
Unknown keys, unknown decoys and unknown detector ids are all startup errors for that reason:
a misspelling can never quietly leave something on.
</details>

## What you learned

- Standalone reads every body, 404s anything unflagged, and blocks on score
- `config` and `check` validate a file without binding a honeypot port; bad config exits 2
- The startup line is the place to confirm the service is what you meant
- Protocol listeners are off by default, fake everything, and share one store and one score

## Where to read more

- [Running it standalone](../start/standalone.md) — the service, signals, Docker
- [The command line](../testing/cli.md) — every command and flag
- [Configuration](../reference/configuration.md) — every section and key
- [Protocol honeypots](../protocols/index.md) — [SSH](../protocols/ssh.md), [SMTP](../protocols/smtp.md), [FTP](../protocols/ftp.md), [Telnet](../protocols/telnet.md), [port scans](../protocols/port-scan.md)

Next: [Operating it](12-operating-it.md).
