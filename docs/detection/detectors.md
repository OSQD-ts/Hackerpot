# The detectors

Every HTTP detector: what it reads, its default score, its options, and whether it can be proof.

← [Documentation](../index.md) · [Detection](index.md)

---

Each entry names four things:

- **reads** — `headers` for the first pass only, `body` when it also inspects the body in the
  [second pass](../concepts/how-it-works.md#two-passes-so-a-body-is-never-read-for-nothing);
- **state** — `per-request`, or the window it needs;
- **score** — the default;
- **proof** — whether it can mark a detection `certain`. Only proof lets a middleware block
  stick; see [the proof guard](../concepts/the-guard.md).

Every factory also accepts `score` and `respondWith`, and every TOML section `enabled`,
`score` and `respond_with`, so those are not repeated below.

## Summary

| Detector | Catches | Reads | Score | Proof | Default |
| --- | --- | --- | --- | --- | --- |
| [`decoy-path`](#decoy-path) | bait paths only an attacker would know | headers | per decoy, 3–10 | no | on |
| [`payload-injection`](#payload-injection) | traversal, SQLi, XSS, command and template injection, Log4Shell, XXE | body | 10 | no | on |
| [`ssrf-probe`](#ssrf-probe) | a value pointing the server at an internal address or a non-HTTP scheme | body | 9 | no | on |
| [`nosql-injection`](#nosql-injection) | MongoDB operators in a query key or JSON body | body | 9 | no | on |
| [`prototype-pollution`](#prototype-pollution) | `__proto__` or `constructor.prototype` in query or body | body | 8 | no | on |
| [`insecure-deserialization`](#insecure-deserialization) | a serialized-object blob in query, cookie or body | body | 9 | no | on |
| [`graphql-abuse`](#graphql-abuse) | schema introspection, pathologically deep queries | body | 7 | no | on |
| [`jwt-weakness`](#jwt-weakness) | a JWT with `alg:none` or an empty signature | headers | 9 | no | on |
| [`crlf-injection`](#crlf-injection) | a CRLF smuggled into path, query or a header | headers | 8 | no | on |
| [`web-shell`](#web-shell) | web-shell filenames, upload-dir scripts, command-exec parameters | headers | 9 | no | on |
| [`header-anomaly`](#header-anomaly) | absolute-form targets, Shellshock, CL+TE smuggling, missing Host, query floods | headers | 7 (up to 10) | no | on |
| [`header-integrity`](#header-integrity) | repeated framing headers, connection headers over HTTP/2 | headers | 9 | **yes** | on |
| [`target-integrity`](#target-integrity) | a target spelled to evade path filters | headers | 7 (weak 3) | no | on |
| [`host-header-injection`](#host-header-injection) | a malformed, duplicated or off-list Host | headers | 6 | no | on |
| [`sensitive-file`](#sensitive-file) | backups, dumps, source copies, VCS and IDE metadata | headers | 6 | no | on |
| [`open-redirect`](#open-redirect) | a redirect parameter carrying an off-site target | headers | 5 | no | on |
| [`suspicious-method`](#suspicious-method) | WebDAV, `TRACE`, `TRACK`, `DEBUG`, `CONNECT` | headers | 6 | no | on |
| [`credential-bruteforce`](#credential-bruteforce) | repeated attempts against one login endpoint | headers | 9 | no | on |
| [`path-bruteforce`](#path-bruteforce) | many distinct paths in a short window | headers | 8 | no | on |
| [`scanner-signature`](#scanner-signature) | scanner and scripting-client User-Agents | headers | 6 | **attack tools** | on |
| [`client-anomaly`](#client-anomaly) | a browser User-Agent missing every browser header | headers | 4 | no | on |
| [`rate-spike`](#rate-spike) | an abnormal request rate | headers | 4 | no | on |
| [`repeat-actor`](#repeat-actor) | one fingerprint attacking from several addresses | headers | 7 | no | on |
| [`honeytoken`](#honeytoken) | a seeded fake credential, replayed | body | 15 | **yes** | opt-in |
| [`trap`](#trap) | a hidden trap link, field or header | headers | 15 | **yes** | opt-in |
| [`crawler-verification`](#crawler-verification) | a crawler claim that DNS or published ranges refute | headers | 10 | **yes** | opt-in |

---

## Paths and files

### `decoy-path`

**headers · per-request · per decoy · not proof**

Requests to bait paths only an attacker would know: `.env` and its variants, `.git`, cloud
and SSH credentials, admin panels, framework debug endpoints, known RCE probes. Forty
built-in decoys, each with its own score, response and fake payload.

A decoy is not proof, deliberately: no link leads to `/.env`, but a URL is text the client
typed, and the client might be your own security engineer checking the site.

```ts
decoyPathDetector()                       // the 40 built-in decoys
decoyPathDetector([...defaultDecoyPaths, myDecoy])
```

Everything about decoys — prefix matching, custom decoys, disabling built-ins, robots.txt —
is on [the decoys page](decoys.md).

### `sensitive-file`

**headers · per-request · 6 · not proof**

Risky file types anywhere on the site: backup, dump and source copies (`.sql`, `.bak`,
`.old`, `~`), VCS and IDE metadata (`/.svn/`, `/.hg/`, `.DS_Store`).

| Option | TOML | Default |
| --- | --- | --- |
| `patterns` | `patterns` (regex list) | `sensitiveFilePatterns`; setting it **replaces** the list |

### `web-shell`

**headers · per-request · 9 · not proof**

Post-exploitation rather than recon: a request for a known web-shell filename (`c99`, `r57`,
`wso`…), an executable script served from an upload or temp directory, or a script URL
carrying a command-execution parameter.

| Option | TOML | Default |
| --- | --- | --- |
| `patterns` | `patterns` (regex list) | `webShellPatterns`; setting it replaces the list |

## Payloads

### `payload-injection`

**body · per-request · 10 · not proof**

Exploitation payloads in the path, the query, listed headers and the body: path traversal,
SQL injection, XSS, command and template injection, Log4Shell (`${jndi:`), XXE. Its
signatures are exported as `injectionSignatures`.

Values containing none of the characters a payload needs skip the patterns entirely, which
makes long ordinary query strings cheap. Traversal findings carry family `path-traversal`,
shared with `target-integrity`, so one encoded traversal counts once.

| Option | TOML | Default |
| --- | --- | --- |
| `inspectBody` | `inspect_body` | `true` |
| `inspectHeaders` | `inspect_headers` | `["user-agent", "referer", "x-forwarded-for", "x-api-version", "cookie"]`; setting it replaces the list |

Log4Shell and friends arrive through headers, which is why User-Agent and Referer are in
the default list.

### `ssrf-probe`

**body · per-request · 9 · not proof**

A parameter, header or body value pointing the server at cloud metadata
(`169.254.169.254`), loopback or an RFC 1918 address, or at a non-HTTP scheme (`file://`,
`gopher://`).

| Option | TOML | Default |
| --- | --- | --- |
| `inspectBody` | `inspect_body` | `true` |
| `inspectHeaders` | `inspect_headers` | `["referer", "destination", "x-original-url", "x-rewrite-url"]` |

The `X-Forwarded-*` and `Forwarded` family is deliberately absent: a proxy legitimately
puts internal addresses there, and scanning them would flag every proxied request. Re-add
them only if nothing trusted sits in front.

### `nosql-injection`

**body · per-request · 9 · not proof**

A MongoDB operator smuggled through a query key's bracket form (`password[$ne]=`) or a JSON
key (`{"password":{"$ne":null}}`, `$where`, `$regex`, `$gt`). Matched as a key, never as
bare text, so an ordinary value containing a `$` does not trip it.

| Option | TOML | Default |
| --- | --- | --- |
| `inspectBody` | `inspect_body` | `true` |

### `prototype-pollution`

**body · per-request · 8 · not proof**

`__proto__`, or `constructor` reaching for `prototype`, in query keys, query values or the
body, including the JSON-nested `{"constructor":{"prototype":…}}`. The shapes that corrupt
`Object.prototype` through a naive deep merge, escalating to privilege escalation or RCE in
some stacks. `__proto__` never appears in legitimate input.

| Option | TOML | Default |
| --- | --- | --- |
| `inspectBody` | `inspect_body` | `true` |

### `insecure-deserialization`

**body · per-request · 9 · not proof**

A serialized-object payload: Java (`rO0AB…`), PHP (`O:<n>:"Class":`), .NET
BinaryFormatter and ViewState, Python pickle, Ruby Marshal, `node-serialize`. The payloads
that turn a `deserialize()` call into remote code execution, and they often ride in cookies.

| Option | TOML | Default |
| --- | --- | --- |
| `inspectBody` | `inspect_body` | `true` |
| `inspectHeaders` | `inspect_headers` | `["cookie", "x-serialized", "viewstate", "__viewstate"]` |

### `graphql-abuse`

**body · per-request · 7 · not proof**

Schema introspection (`__schema`, `IntrospectionQuery`: how an attacker dumps your whole API
surface) and queries nested past `maxDepth` braces, used for resource exhaustion.

| Option | TOML | Default |
| --- | --- | --- |
| `maxDepth` | `max_depth` | `12` |
| `inspectBody` | `inspect_body` | `true` |

Raise `max_depth` if you legitimately serve deep queries; disable the detector if you expose
a public GraphQL API where introspection is a supported feature.

### `jwt-weakness`

**headers · per-request · 9 · not proof**

A JWT whose header declares `alg:"none"` (an unsigned token crafted to impersonate anyone),
or one presented with an empty signature, in a listed header or any query value. A real
token is always signed.

| Option | TOML | Default |
| --- | --- | --- |
| `inspectHeaders` | `inspect_headers` | `["authorization", "cookie", "x-access-token"]` |

### `crlf-injection`

**headers · per-request · 8 · not proof**

A carriage return and line feed smuggled into the path, a query value or a header, to inject
response headers or poison a cache.

| Option | TOML | Default |
| --- | --- | --- |
| `inspectHeaders` | `inspect_headers` | `["referer", "x-forwarded-for", "user-agent"]` |

`X-Forwarded-For` is safe to scan here: a normal one never contains a CRLF.

### `open-redirect`

**headers · per-request · 5 · not proof**

A redirect-style parameter (`redirect`, `redirect_uri`, `url`, `next`, `return`, `goto`,
`dest`, `continue`, `target`…) carrying an off-site target: `//evil.example`,
`https://evil.example`, or an `@` or backslash trick. A phishing bounce off your domain, or
OAuth `redirect_uri` abuse.

| Option | TOML | Default |
| --- | --- | --- |
| `params` | `params` | the built-in list; setting it replaces it |
| `trustedHosts` | `trusted_hosts` | unset: the request's own `Host` counts as same-site |

Only off-site targets fire. Without `trustedHosts` the detector treats the request's `Host`
as same-site, which is convenient and client-controlled; pin your real hostnames to make the
list authoritative.

## Protocol and headers

### `header-anomaly`

**headers · per-request · 7, specific findings higher · not proof**

| Finding | Score |
| --- | --- |
| Shellshock (`() {`) in any header | 10 |
| both `Content-Length` and `Transfer-Encoding` (request smuggling indicator) | 9 |
| absolute-form request target (open-proxy probing) | 8 |
| more than 256 query parameters (only the first 256 are inspected, so the flood itself is flagged) | 7 |
| missing `Host` on a non-`OPTIONS` request (`:authority` counts over HTTP/2) | 7 |

| Option | TOML | Default |
| --- | --- | --- |
| `flagMissingHost` | `flag_missing_host` | `true` |

The missing-Host check stands down on facts rebuilt from a log (`partialHeaders`), where no
line records a Host.

### `header-integrity`

**headers · per-request · 9 · proof for protocol violations**

Protocol violations read from what the request **contains**, never from what it lacks:

| Finding | Score | Proof |
| --- | --- | --- |
| a repeated `Host` or `Content-Length` | 9 | **yes** |
| a connection-specific header (`Connection`, `Keep-Alive`, `Transfer-Encoding`…) over HTTP/2 or HTTP/3 | 9 | **yes** |
| a header no browser repeats (`User-Agent`, `Accept`…) sent twice over HTTP/1.x | 3 | no |

| Option | TOML | Default |
| --- | --- | --- |
| `duplicateScore` | `duplicate_score` | `3`; `0` ignores duplicates |

No shipping client stack emits the first two, because a compliant proxy must reject them;
the repeated framing headers are the ambiguity request smuggling is built on. It needs
`rawHeaders`, which Node's server and the adapters supply.

### `target-integrity`

**headers · per-request · 7 or 3 · not proof**

Reads the request target **as sent** (`rawPath`), which every other detector sees only
after normalisation:

| Finding | Score |
| --- | --- |
| double encoding, an encoded control character, an encoded traversal | `score` (7) |
| a plain `..`, or an encoded slash inside a segment (broken clients send these too) | `weakScore` (3) |

| Option | TOML | Default |
| --- | --- | --- |
| `weakScore` | `weak_score` | `3` |

Family `path-traversal` for traversals, `evasive-target` otherwise.

### `host-header-injection`

**headers · per-request · 6 · not proof**

A manipulated `Host` or `X-Forwarded-Host`, used to poison password-reset links, absolute
URLs or a cache.

| Option | TOML | Default |
| --- | --- | --- |
| `expectedHosts` | `expected_hosts` | unset |

Without `expectedHosts`, only structural problems fire: a duplicated `Host`, or one with
characters a host never has. A differing `X-Forwarded-Host` is normal behind a proxy and is
not judged without the list. With it, anything off the list fires. Entries are hostnames,
**lowercase and without a port**: the incoming port is stripped before comparison, so an
entry with a port could never match, and the config refuses one.

### `suspicious-method`

**headers · per-request · 6 · not proof**

HTTP methods no browser or ordinary API client sends.

| Option | TOML | Default |
| --- | --- | --- |
| `methods` | `methods` | `TRACE`, `TRACK`, `DEBUG`, `CONNECT`, `PROPFIND`, `PROPPATCH`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`, `SEARCH` (`defaultSuspiciousMethods`) |

`jwt-weakness` and `crlf-injection` also read headers; they are under [payloads](#payloads)
above.

## Clients

### `scanner-signature`

**headers · per-request · 6 · proof for attack tools**

| Match | Proof |
| --- | --- |
| an attack tool naming itself: `sqlmap`, `nikto`, `nmap`, `masscan`, `zgrab`, `zmap`, `dirbuster`, `dirb`, `gobuster`, `feroxbuster`, `ffuf`, `wfuzz`, `nuclei`, `acunetix`, `nessus`, `openvas`, `qualys`, `arachni`, `w3af`, `metasploit`, `hydra`, `havij`, `burpsuite` (`attackToolUserAgentPatterns`) | **yes** |
| a bare scripting client: `curl/`, `wget/`, `python-requests`, `Go-http-client`, `libwww-perl` (`scriptingClientUserAgentPatterns`) | no |
| a pattern you added | no |
| no User-Agent at all (scores half) | no |

| Option | TOML | Default |
| --- | --- | --- |
| `extraPatterns` | `extra_patterns` (regex list) | none; appended |
| `flagMissingUserAgent` | `flag_missing_user_agent` | `true` |

A tool naming itself is its own statement of what it is. A scripting client is also every
legitimate script and integration, which is why it scores modestly and never proves.
`scannerUserAgentPatterns` is both lists, and is what the nginx generator reuses.

### `client-anomaly`

**headers · per-request · 4 · not proof**

A User-Agent claiming a mainstream browser while sending **none** of the headers every real
browser sends unconditionally. A "Chrome" with no `Accept-Language` is a script wearing a
browser's name. It only fires on a User-Agent that claims to be a browser, so an honest
`curl` never trips it; and only when every listed header is missing, because a stripping
proxy can remove one.

| Option | TOML | Default |
| --- | --- | --- |
| `requiredBrowserHeaders` | `required_browser_headers` | `["accept", "accept-language", "accept-encoding"]` |

Weak and easily evaded, so it scores low and matters as corroboration. It stands down on
`partialHeaders`.

## Behaviour over time

These read the address's [activity window](../concepts/actors.md#what-is-remembered-per-address),
so `[engine] activity_window_ms` must be at least as long as their windows. A crawler that
`crawler-verification` confirmed is exempt from `rate-spike` and `path-bruteforce`.

### `credential-bruteforce`

**headers · stateful · 9 · not proof**

Repeated `POST`, `PUT` or `PATCH` attempts against one authentication endpoint from one
address: credential stuffing, password spraying.

| Option | TOML | Default |
| --- | --- | --- |
| `authPaths` | `auth_paths` (regex) | `(login\|signin\|sign-in\|auth\|token\|oauth\|session\|password\|wp-login\.php)` |
| `windowMs` | `window_ms` | `60000` |
| `attemptThreshold` | `attempt_threshold` | `8` |

It counts every attempt in middleware mode too: repeated attempts on one path are exactly
what it measures.

### `path-bruteforce`

**headers · stateful · 8 · not proof**

One address requesting many **distinct** paths fast: a wordlist walk. A busy client polling
one endpoint never trips it.

| Option | TOML | Default |
| --- | --- | --- |
| `windowMs` | `window_ms` | `30000` |
| `uniquePathThreshold` | `unique_path_threshold` | `15` |

In middleware mode a path handed to your app counts only once the app answers **404**, so
the twenty asset paths of one page load are not enumeration. See
[adapters](../integration/adapters.md#path-bruteforce-in-front-of-real-users) for apps that
answer unknown paths with 200.

### `rate-spike`

**headers · stateful · 4 · not proof**

A raw request-rate flood from one address. The noisiest signal there is — a NAT, a
university and a CGNAT pool are all one address — so it scores low and matters when it
stacks with something specific.

| Option | TOML | Default |
| --- | --- | --- |
| `windowMs` | `window_ms` | `10000` |
| `requestThreshold` | `request_threshold` | `60` |

Raise the threshold if one of your pages legitimately makes sixty requests.

### `repeat-actor`

**headers · correlating · 7 · not proof**

One [actor fingerprint](../concepts/actors.md#the-actor-fingerprint) seen attacking from
several addresses: someone rotating addresses to dodge per-address blocking.

| Option | TOML | Default |
| --- | --- | --- |
| `distinctIpThreshold` | `distinct_ip_threshold` | `3` |
| `windowMs` | `window_ms` | `600000` |

Safe in front of real users: the registry holds only addresses whose requests already
scored, and the current address must be one of them. It confirms that suspicious addresses
are one actor, and never manufactures suspicion. See [actors](../concepts/actors.md#cross-ip-correlation-repeat-actor).

## Planted proof

### `honeytoken`

**body · per-request · 15 · proof · opt-in**

A seeded fake credential, key or id replayed anywhere in the request: path, raw path, query
values, every header, and the body. `Authorization` and `Proxy-Authorization` Basic values
are base64-decoded first, so a token replayed as a Basic password is caught. See
[honeytokens](traps-and-honeytokens.md#honeytokens).

| Option | TOML | Default |
| --- | --- | --- |
| `tokens` | `tokens` (strings, or tables with `value` and `label`) | required; listing any enables it |

### `trap`

**headers · per-request · 15 · proof · opt-in**

A request for a trap path, a filled-in trap form field, or the trap header. See
[hidden traps](traps-and-honeytokens.md#hidden-traps).

| Option | TOML | Default |
| --- | --- | --- |
| `paths` | `paths` | `DEFAULT_TRAP_PATHS`: `/internal/export.csv`, `/api/v1/all-users`, `/sitemap-index-full.xml` |
| `formFields` | `form_fields` | none |
| `headerName` | `header_name` | none |

### `crawler-verification`

**headers · verifying · 10 · proof · opt-in**

A User-Agent claiming Googlebot, Bingbot, Applebot, YandexBot, Baiduspider and eleven
others, from an address that forward-confirmed reverse DNS or the operator's published
ranges refute. A confirmed crawler is exempt from `rate-spike` and `path-bruteforce`. See
[verification](verification.md).

| Option | TOML | Default |
| --- | --- | --- |
| `treatMissingPtrAsForgery` | `treat_missing_ptr_as_forgery` | `true` |
| `ranges` | `published_ranges` | unset / `false` |
| — | `ranges_refresh_hours` | `12` |
| `resolver` | — | Node's resolver behind a cache |
| `crawlers` | — | `verifiableCrawlers` |

## Related

- [Detection overview](index.md) — sets, shared options, normalisation
- [The proof guard](../concepts/the-guard.md) — why the proof column matters
- [Configuration](../reference/configuration.md#detectors) — the TOML sections in one place
- [Writing a detector](writing-a-detector.md)
