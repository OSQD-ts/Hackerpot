# Try it locally

The demo, the simulator and the dashboard on your own machine.

← [Documentation](../index.md) · [Testing](index.md)

---

Three commands show the whole library working, with nothing to configure and nothing reaching beyond
loopback:

```bash
npm install
npm run demo        # terminal 1: every listener, and the dashboard
npm run simulate    # terminal 2: an attack for every detector
```

Then open **http://127.0.0.1:9501/**.

The simulator exists to exercise this project's own detectors against this demo. Point it at nothing
else.

---

## `npm run demo`

`demo/server.ts` starts every kind of honeypot the library has, sharing one memory store, with the
library's own dashboard reading it:

```text
honeypot         http://localhost:4004
dashboard        http://127.0.0.1:9501/
management API   http://127.0.0.1:9500  (API key "dev-key")
port sentinels   TCP 8022, 9200, 7001
SSH 2222 · SMTP 2525 · FTP 2121 · Telnet 2323
25 detectors, 12 response actions.

Generate traffic:  npm run simulate      (or npm run simulate:corpus)
```

| Listener | Port | Move it with |
| --- | --- | --- |
| HTTP honeypot, the one attackers hit | `4004` | `PORT` |
| [Dashboard](../operations/dashboard.md) | `9501` on `127.0.0.1` | `GUI_PORT` |
| [Management API](../operations/management-api.md): REST, the live WebSocket, `/metrics` | `9500` on `127.0.0.1` | `MGMT_PORT`; key `MGMT_API_KEY`, default `dev-key` |
| [SSH](../protocols/ssh.md) | `2222` | `SSH_PORT` |
| [SMTP](../protocols/smtp.md) | `2525` | `SMTP_PORT` |
| [FTP](../protocols/ftp.md) | `2121` | `FTP_PORT` |
| [Telnet](../protocols/telnet.md) | `2323` | `TELNET_PORT` |
| [Port-scan sentinels](../protocols/port-scan.md) | `8022`, `9200`, `7001` | `SCAN_PORTS` (comma-separated) |

A port that is taken does not stop the demo. That listener is skipped with a line saying which variable
to set, for example `dashboard not started: TCP 9501 is in use. Set GUI_PORT=<free port>.`, and the rest
start.

What is different from a real deployment, on purpose:

- **It trusts `X-Forwarded-For`.** The simulator gives each scenario its own address that way, so one
  scenario's score cannot get the next blocked before its detector is seen. The shipped service does not
  trust it, and [should not](../integration/client-ip.md) unless a proxy you control sets it.
- **The policy routes a few probes to the showier responses** so they can be seen working: `web-shell`
  gets `fake-success`, `ssrf-probe` gets `gzip-bomb`, `open-redirect` gets `rate-limit` and
  `crlf-injection` gets `chaos`. Anything the default policy would block is still blocked.
- **FTP and Telnet are interactive**, so you can see what gets typed after a login.
- **A honeytoken and a trap are seeded**: `AKIA_HACKERPOT_HONEYTOKEN_DEMO` and the corpus's token, and
  the trap path `/internal/export.csv` with the corpus's hidden form field.
- **The dashboard has no authentication.** It binds loopback, where the operating system is the access
  control.

Every incident is printed as it happens:

```text
[hit] 2026-09-15T17:00:32.908Z ip=100.111.113.10 GET /wso.php score=+15 total=15 -> fake-success
      detections: web-shell(Web-shell probe: /wso.php), scanner-signature(User-Agent matches known tooling signature: curl/8.4.0)
```

The address, what was requested, the score this request added and the address's running total, the
response served, and each detection with the reason its detector gave. `[port-touch]` and `[PORT-SCAN]`
lines come from the sentinels.

Everything lives in memory and is gone when you stop the demo with Ctrl+C.

---

## `npm run simulate`

`scripts/simulate.ts` points realistic attacks at the demo, then asks the demo's management API what the
honeypot concluded about each. With no argument it runs every scenario; name one to run it alone.

```bash
npm run simulate                     # every scenario
npm run simulate:web-shell           # one
npm run simulate -- ssh ftp          # several
npm run simulate:list                # what there is
```

```text
$ npm run simulate:list
decoys                     paths only an attacker would know: .env and its variants, .git, cloud credentials, framework debug endpoints
path-bruteforce            a wordlist walk: twenty paths that do not exist, fast
credential-bruteforce      ten guesses against one login endpoint
rate-spike                 eighty requests at once from one address
scanner-signature          tools that announce themselves in the User-Agent
payload-injection          traversal, SQL injection, XSS, Log4Shell and command injection
suspicious-method          verbs no browser sends
sensitive-file             backup, dump, source and version-control files
header-anomaly             Shellshock, request smuggling framing, an absolute-form target
header-integrity           a repeated Host header, which no client stack sends
ssrf-probe                 pointing the server at cloud metadata, file:// and loopback services
open-redirect              bouncing a victim off-site through a redirect parameter
crlf-injection             smuggling a header through CR/LF in a parameter
nosql-injection            MongoDB operators in a query key and in a login body
graphql-abuse              schema introspection and a deeply nested query
jwt-weakness               a forged alg:none token
client-anomaly             a Chrome User-Agent with none of the headers Chrome sends
prototype-pollution        __proto__ in a query key and a JSON body
insecure-deserialization   a Java serialized object in a cookie, a PHP object in a form
host-header-injection      a Host header carrying a path, for password-reset poisoning
web-shell                  reaching for a dropped backdoor
honeytoken                 replaying a credential planted in a decoy .env
trap                       following a link that is hidden from people and disallowed in robots.txt
port-scan                  sweeping the port-scan sentinels
smtp                       AUTH brute force, open relay, VRFY enumeration
ssh                        password brute force
ftp                        brute force, an FTP bounce and a traversal
telnet                     the default credentials the Mirai lineage sprays, then a dropper
```

Every scenario has an `npm run simulate:<name>` script except `header-integrity`; run that one as
`npm run simulate -- header-integrity`.

### Reading the output

```text
$ npm run simulate:web-shell
Target http://127.0.0.1:4004 · management API http://127.0.0.1:9500 · dashboard http://127.0.0.1:9501/

# web-shell — reaching for a dropped backdoor   (from 100.111.113.10)
    known web-shell filename                             200     11ms
    script in an upload directory                        200      4ms
  → fired web-shell, scanner-signature; responded fake-success
```

- **The header line** is where it is aiming. A scenario starts with `#`, its description, and the source
  address it sends as.
- **Each request** is a label, the status the honeypot answered, and how long the answer took. `200`
  here is the demo's `fake-success` pretending the shell is there. `---` with "held open (tarpit?)" is a
  response that is slow on purpose; the status line is all the simulator waits for.
- **The arrow line** is read back from the management API: every detector that fired from that address,
  and every response served. `MISSING` after it names an expected detector that did not fire.

The addresses are random on every run (a fresh `/24` from `100.64.0.0/10`), because the demo remembers
scores and blocks for as long as it runs and a second run from the same addresses would be answered by
the first run's blocks. Timings vary too. The detectors and responses are the stable part.

The protocol scenarios (`port-scan`, `smtp`, `ssh`, `ftp`, `telnet`) print what the server answered (SMTP
and FTP reply codes, accepted or rejected logins, banners) and are not checked against the API; watch the
demo's terminal and the dashboard for them.

Two things end a run with exit code `1` and a line saying so: a scenario whose expected detector did not
fire, and a target that answered most requests with `403`. The second means the target is not trusting
`X-Forwarded-For`, so every scenario landed on one address and it was blocked in the first one. It is
what you see pointing the simulator at the shipped service instead of the demo. If the management API
does not answer, the run says it cannot show what fired.

| Environment | Default |
| --- | --- |
| `HONEYPOT_URL` | `http://127.0.0.1:4004` |
| `MGMT_URL`, `MGMT_API_KEY` | `http://127.0.0.1:9500`, `dev-key` |
| `GUI_PORT` | `9501` (only printed) |
| `HONEYTOKEN`, `TRAP_PATH` | the demo's seeded values |
| `SCAN_PORTS`, `SSH_PORT`, `SMTP_PORT`, `FTP_PORT`, `TELNET_PORT` | the demo's ports |

Set the same variables for both commands when you move a port.

---

## `npm run simulate:corpus`

The labelled [traffic corpus](corpus.md), sent down real sockets to the demo and checked against its
management API:

```text
$ npm run simulate:corpus

# corpus — 159 cases over raw sockets, checked against the management API at http://127.0.0.1:9500


  131 passed, 0 failed on the wire.
  2 refused by Node's HTTP parser before reaching the honeypot: request-smuggling-cl-te, missing-host-header
  known cost: wordpress-author-wp-login (fired decoy-path)
  9 skipped: is paced over time, which only the in-process clock reproduces
  12 skipped: needs crawler-verification
  3 skipped: needs crawler-verification, published-ranges
  1 skipped: is HTTP/2, which this raw HTTP/1.1 client cannot send
```

`simulate:corpus:human` replays only the human cases, which is the quickest way to watch people go
through without anything firing. What each line means, and why the skipped cases cannot be replayed
here, is in [the corpus](corpus.md#replaying-it-over-real-sockets).

---

## `npm run demo:embedded`

The same dashboard as `<hackerpot-dashboard>`, inside an admin page of its own:

```text
$ npm run demo:embedded
admin panel with an embedded dashboard   http://127.0.0.1:9675/
sign in as demo / hackerpot
120 probes evaluated, so there is something to look at.
```

It needs neither the demo nor the simulator: it evaluates a spread of probes through its own engine
before the page opens. Move it with `ADMIN_PORT`, change the password with `ADMIN_PASSWORD`. What it
demonstrates, same-origin mounting and a shadow root that is not a security boundary, is in [Embedding
the dashboard](../operations/embedding.md).

## The dashboard beside the demo

The demo's dashboard reads the engine in the same process. The same page as a separate service, reading
the demo's management API the way it would read a real stack's, is one more terminal:

```text
$ npm run dashboard -- --port 9502 --management-url http://127.0.0.1:9500 --api-key dev-key
{"ts":"2026-09-15T17:02:36.493Z","kind":"startup","service":"dashboard","url":"http://127.0.0.1:9502/","source":"management API at 127.0.0.1:9500"}
```

Open both and compare: the header says "this process" on one and "management API at 127.0.0.1:9500" on
the other, and the incidents are the same. See [running it as its own
service](../operations/dashboard.md#as-its-own-service-beside-the-stack).

---

## What to look at in the dashboard

Open http://127.0.0.1:9501/ before running the simulator, and watch it fill in.

- **The status in the header** says `live`. Incidents arrive as the simulator sends them, and the
  Incidents tab's count climbs without a refresh.
- **Overview** after a full run: `scanner-signature` near the top of detections by type (the simulator
  mostly sends `curl`), the response mix showing the demo policy's `fake-success`, `gzip-bomb`,
  `rate-limit` and `chaos` beside the default policy's own answers, and the top offenders by score.
- **Incidents**: filter the detector to `web-shell` and open a row. *Why this fired* explains
  `web-shell` and `scanner-signature`; *Response* explains `fake-success`. Then open a `payload-injection`
  row from the `UNION SELECT` or the Log4Shell request and read **Decoded payloads**: the URL-encoded
  query peeled back to what it says.
- **Incidents** again, for `honeytoken`: the `Authorization` header shows `[redacted]`, because
  credential redaction is on by default. The detection still says the token was replayed.
- **Statistics**: the **Protocol split** after `npm run simulate -- ssh smtp ftp telnet`, the
  **detector co-occurrence** matrix (which detectors fire together), and the **escalation funnel** showing
  how far each address got.
- **Sessions**: one scenario's address, in order, as a timeline. `credential-bruteforce` reads well here:
  ten posts to `/login`, with the score accumulating until the detector fires.
- **Actors**: after `npm run simulate:corpus`, the `distributed-rotating-addresses` case is one
  fingerprint (the same `python-requests` headers) across three addresses.
- **Threat intel**: every address the simulator used with its score, and the Prometheus text at the
  bottom; `hackerpot_incidents_total` matches the Overview's count.
- **Turn Live feed off**, run a scenario, and turn it back on: the page reloads what it missed.

The page names its instance `demo` and its source `this process`. The same page on your own deployment
is [the dashboard](../operations/dashboard.md); a walk through all of it with a running example is
[the course](../course/index.md).

---

## Related

- [The traffic corpus](corpus.md): what `simulate:corpus` replays, and `npm run corpus` in process
- [The dashboard](../operations/dashboard.md) and [Embedding it](../operations/embedding.md)
- [The command line](cli.md): `hackerpot explain` for one request, `hackerpot replay` for a log
- [Standalone service](../start/standalone.md): the real thing, without the demo's shortcuts
