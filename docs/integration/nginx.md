# nginx edge capture

Diverting statically recognisable probes at the edge, so they never touch your application.

← [Documentation](../index.md) · [Integration](index.md)

---

If nginx sits in front of your application, it can catch the *statically recognisable* attacks and
reverse-proxy them to a standalone honeypot, so they never reach your real backend. The config is
generated from the detector definitions, so regenerating keeps it in step.

```bash
npm run generate:nginx                                   # writes three files into nginx/
npm run generate:nginx -- --upstream 10.0.0.5:4004       # point at your honeypot host
npm run generate:nginx -- --server-name shop.example.com --app-upstream 127.0.0.1:8000
npm run generate:nginx -- --stdout                       # print instead of writing
npm run generate:nginx -- --no-injection                 # skip the URI-injection map
```

| Flag | Default |
| --- | --- |
| `--upstream <host:port>` | `127.0.0.1:4004`: the honeypot |
| `--app-upstream <host:port>` | `127.0.0.1:3000`: your app, for the example vhost |
| `--server-name <name>` | `example.com`, for the example vhost |
| `--out-dir <dir>` | `nginx` |
| `--prefix <dir>` | `/etc/nginx`, for the printed instructions |
| `--stdout` | print every file instead of writing |
| `--no-injection` | skip the best-effort URI-injection map |

The generator runs from a clone of the repository; `nginx/` is generated output and ignored by git.

## Three files, one per context

`include` in nginx is a verbatim textual splice, so a file can only be included into the context its
directives belong to. Each carries its own install instructions in its header.

| File | Goes to | Context |
| --- | --- | --- |
| `hackerpot-http.conf` | `/etc/nginx/conf.d/` | `http {}`, once per host |
| `hackerpot-server.conf` | `/etc/nginx/snippets/` | `server {}`, once per protected vhost |
| `hackerpot-site.conf.example` | `/etc/nginx/sites-available/` | a complete worked vhost |

## What the edge diverts: read this before enabling it

The in-process middleware is conservative: anything no detector flags falls through untouched. **The
edge is not the same trade.** It classifies on `$uri`, `$request_method`, `$http_user_agent` and
`$request_uri` alone, with no idea whether the client is legitimate, so two rules divert real traffic:

- **`$hp_bad_file` matches by extension**, anywhere on the vhost: `.zip`, `.tar`, `.tar.gz`, `.tgz`,
  `.gz`, `.rar`, `.7z`, `.bz2`, `.sql`, `.sqlite`, `.db`, `.dump`, `.bak`, `.old`, `.orig`, `.save`,
  `.swp`, `.tmp`, `.log`, `.DS_Store`, and `.git`, `.svn`, `.idea`, `.vscode` paths. A site that serves
  release archives, database exports or log downloads will have those requests answered by the honeypot
  instead of the app, from a real browser with a real session.
- **`$hp_bad_ua` matches the client, not the request**: `curl/`, `wget/`, `python-requests`,
  `go-http-client`, `libwww-perl` and the scanner list. If you run a public API, every legitimate `curl`
  and `requests` client is diverted on *every* path.

Both are deliberate (at the edge, "a browser would never ask for this" is the whole signal) but they are
the difference between "safe next to production" and "safe next to *your* production". Before enabling:

```bash
# Dry-run the classification against your real access log.
awk '{print $7}' /var/log/nginx/access.log | sort -u > /tmp/paths.txt
grep -Ei '\.(zip|tar|tar\.gz|tgz|gz|rar|7z|bz2|sql|sqlite|db|dump|bak|old|orig|save|swp|tmp|log)$' /tmp/paths.txt
```

Anything that returns is a path your users request today that the edge would take away. Either drop that
rule from the generated `map`, or serve those files from a hostname you do not include
`hackerpot-server.conf` into. `--no-injection` removes only the `$hp_bad_uri` map; the file and
User-Agent maps are separate.

The honeypot's own detectors still see everything diverted; the edge only decides what reaches your app.

## Wiring it in

```bash
sudo cp nginx/hackerpot-http.conf   /etc/nginx/conf.d/
sudo cp nginx/hackerpot-server.conf /etc/nginx/snippets/
```

`/etc/nginx/nginx.conf` already ends its `http {}` block with `include /etc/nginx/conf.d/*.conf;`, so the
http half needs no edit. Then add **one line** to the vhost you want protected:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    include snippets/hackerpot-server.conf;   # anywhere inside server {}

    location / {
        proxy_pass http://127.0.0.1:3000;     # your app, untouched
    }
}
```

```bash
sudo ln -s ../sites-available/<yoursite> /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Include paths are relative to the nginx prefix, so `snippets/…` resolves to `/etc/nginx/snippets/…`.
Include the **http** file exactly once: two vhosts pulling it in would define `upstream
hackerpot_backend` twice, and nginx would refuse to start. On RHEL or Alpine there is no `sites-enabled`;
the http file still goes in `conf.d/`, but give the server file a non-`.conf` suffix
(`hackerpot-server.inc`) so the automatic `conf.d/*.conf` include does not load server-context
directives at http level.

## How the diversion works

- **http context**: the `hackerpot_backend` upstream, plus `map`s that flag scanner User-Agents,
  suspicious methods, risky extensions and (best-effort) injection payloads in the URI, combined into one
  `$hp_flagged` variable.
- **server context**: a `location` per decoy path (a case-insensitive regex location for prefix decoys,
  both slash forms for exact ones), and a server-level `if ($hp_flagged)` for every other path. Both just
  `return 418`, an internal marker that `error_page` turns into a jump to a single `@hackerpot` location.
  `return` is the one construct always safe inside `if`, the status never reaches the client, and the
  snippet sets no `proxy_*` at server level, so your own `location` blocks are left exactly as they were.

Flagged requests are `proxy_pass`ed, not HTTP-redirected, so the attacker is transparently served by the
decoy and cannot tell they were diverted. The request line is forwarded raw, so the honeypot's detectors
see the original encoding.

> **Set `trust_proxy = true` on the honeypot.** This is the half of the pair that is easy to miss,
> because nothing looks broken without it. The `X-Forwarded-For` nginx sets is ignored unless the honeypot
> trusts it, so every diverted request is attributed to **nginx's own address**. Hits are still recorded
> and the dashboard still fills up, but every attacker shares one score, `/ioc.txt` exports the proxy's
> address, and once that score crosses the block threshold the honeypot blocks nginx: a 403 for every
> diverted request from everyone. Enable it *only* with this proxy in front, and make sure the honeypot
> is not reachable around it. See [the client IP](client-ip.md).

Two details, both handled in the generated file. nginx rejects `TRACE` and `CONNECT` itself while parsing
the request line, before any config runs, so `405` is routed to `@hackerpot` beside the marker code;
otherwise those verbs would get a stock error page and never be recorded. (Only nginx-generated 405s are
caught; a 405 from your app passes through. If the vhost serves static files, nginx answers `POST` to a
static file with 405 too.) And because nginx has no urldecode, the injection signatures are widened to
match percent-encoded payloads: `union%20select` and `%3Cscript` are what real tooling sends.

## What the edge cannot do

The running honeypot still owns these, because nginx cannot see them statically:

- path and credential brute force, and rate spikes (per-address state);
- injection payloads in bodies and headers;
- honeytokens, traps and crawler verification;
- the port-scan sentinel and the protocol honeypots (below HTTP).

The generated config validates with `nginx -t`.

## Related

- [The client IP](client-ip.md) — the setting this depends on
- [Decoys](../detection/decoys.md) — where the decoy locations come from
- [Running it standalone](../start/standalone.md) — the upstream this points at
