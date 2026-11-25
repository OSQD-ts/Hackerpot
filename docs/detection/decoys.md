# Decoys

The forty built-in bait paths, matching at the root or at any depth, the seeded secrets they serve,
decoys of your own, and robots.txt as a lure.

← [Documentation](../index.md) · [Detection](index.md)

---

A **decoy** is a path only an attacker would know: a leaked `.env`, a `.git` directory, a
phpMyAdmin panel, a framework debug endpoint. No link on your site leads to it, so a request
for it is a probe. `decoy-path` recognises the request, and the decoy says what to serve:
often a convincing fake, so the probe appears to have worked and the attacker keeps going.

## A decoy

```ts
interface DecoyPath {
  id: string;
  description: string;                 // becomes the detection's summary
  path: string | RegExp;               // an exact path, or a pattern
  match?: "exact" | "prefix" | "anywhere"; // for a string path; default "exact"
  method?: string;                     // only this method
  score: number;
  respondWith?: string;                // a response action id
  payload?: { status?: number; contentType?: string; body?: string; location?: string };
}
```

The `payload` is handed to the response action. `decoy-content` serves its status, content
type and body; `redirect` sends its `location`.

## Matching

- A **string path** matches exactly, ignoring a trailing slash: `/wp-login.php` and
  `/wp-login.php/`.
- With **`match: "prefix"`** it also matches anything beneath it or with a suffix after a
  dot, **at a `/` or `.` boundary only**, ignoring case. `/.env` covers `/.env.production`,
  `/.env/` and `/.ENV`; `/.git` covers `/.git/index`; and `/backup` does **not** match
  `/backup-your-data-a-guide`. Scanners probe both spellings, and some servers serve both.
- With **`match: "anywhere"`** it matches as a prefix does, below any directory too: `/.env`
  also covers `/laravel/.env`, `/backup/.env.local` and `/public/.env/`, still only at a `/` or
  `.` boundary, so `/docs/.envelope` and `/x/.github/` do not match. Scanners ask for these once the
  root has been tried. The dotfile and VCS decoys use it, and so does `wp-config`.
- A **RegExp** is tested against the path. A `g` or `y` flag would otherwise make it match
  only every other request, so the detector strips that state.

Every match runs on the normalised path, so `//.env`, `/./.env` and `/%2eenv` are all
`/.env`. See [normalisation](index.md#normalisation-happens-once-before-any-detector).

## The built-in set

`defaultDecoyPaths`, forty entries. `P` marks a prefix match, `A` a match at any depth.

| Group | Decoys (id: path, score, response) |
| --- | --- |
| **Secrets** | `dotenv` `/.env` A 10 fake .env · `git-config` `/.git/config` A 10 fake · `git-head` `/.git/HEAD` A 8 fake · `aws-credentials` `/.aws/credentials` A 10 fake · `ssh-key` `/.ssh/id_rsa` A 10 · `docker-config` `/.docker/config.json` A 8 · `git-dir` `/.git` A 9 · `aws-dir` `/.aws` A 9 · `ssh-dir` `/.ssh` A 9 · `package-credentials` `.npmrc` `.pypirc` `.netrc` `.git-credentials` at any depth 8 · `htpasswd` `/.htpasswd` A 8 · `shell-history` `.bash_history` and friends at any depth 7 |
| **Panels** | `wp-login` `/wp-login.php` 5 fake login page · `wp-admin` `/wp-admin…` 5 redirect to wp-login · `xmlrpc` `/xmlrpc.php` 6 · `phpmyadmin` `/phpmyadmin`, `/pma`, `/adminer.php` 6 fake login · `admin-panel` `/admin`, `/administrator` 4 fake login |
| **Frameworks and servers** | `spring-actuator-env` `/actuator/env` P 8 · `spring-actuator-health` 3 · `spring-actuator-heapdump` 9 · `spring-cloud-gateway-rce` `/actuator/gateway/routes` P 9 · `server-status` 5 · `go-pprof` `/debug/pprof` 7 · `laravel-telescope` 6 · `laravel-ignition-rce` P 10 · `phpunit-eval-rce` `/vendor/phpunit` P 10 · `php-info` 5 · `wp-config` A 7 · `couchdb-all-dbs` `/_all_dbs` 7 · `solr-admin` P 7 · `tomcat-manager` `/manager/html` P 7 · `jenkins-script-console` P 8 · `druid-indexer` P 8 · `geoserver` P 7 · `router-rce` `boaform`, LuCI, HNAP 8 · `fortinet-traversal` `/remote/fgt_lang` P 9 · `yii-debug` P 7 |
| **Generic** | `swagger` `/swagger`, `/api-docs`, `/openapi` 3 · `backup-archive` `/backup.zip`, `/db.sql`, `/dump.tar.gz` 7 · `config-file` `/config.json`, `.php`, `.yml` 5 |

Every decoy without a fake payload answers `not-found`: the probe was the signal, and a flat
404 reveals nothing.

## Seeded secrets

The fake `.env`, `.aws/credentials` and `.git/config` carry values generated from a seed
(`decoySecrets(seed)`): an `APP_KEY`, a database name, user and password, an AWS-shaped access key
and secret, and a git remote. They used to be constants, AWS's documentation key
`AKIAIOSFODNN7EXAMPLE` and `github.com/example/example.git`, identical in every install; a scanner
that had met one HackerPot had met them all, and a well-known example key is the first thing a
harvesting tool learns to skip.

- **Different per install.** With no seed configured, `DEFAULT_DECOY_SEED` is random per process start,
  so the values change on every restart. Set `[detectors.decoy-path] seed` (at least 16 random
  characters, for example `openssl rand -hex 16`) to keep them stable, so a returning prober sees a
  consistent file. In code, `decoyPathsFor(seed)` is the built-in set for a seed.
- **Pointing at nobody else.** The database host is the loopback address and the git remote is under
  `.internal`, a name reserved never to resolve on the public internet. An attacker following the
  bait only ever reaches you, or nothing.
- **Honeytokens by construction.** The values exist only in what the decoys hand out, so one coming
  back is somebody using what they harvested. `decoyHoneytokens(seed)` lists the long ones, and they
  are watched by default (`[detectors.decoy-path] honeytokens = true`); see
  [honeytoken](detectors.md#honeytoken).

## Before you deploy: does your site serve any of these?

A decoy that shadows a real route breaks that route for everyone, because the honeypot
answers first. Common collisions: a real Swagger or OpenAPI document (`swagger`), a real
`/admin` (`admin-panel`), a Spring Boot health check at `/actuator/health`. Drop them:

```toml
[detectors.decoy-path]
disabled = ["swagger", "admin-panel", "spring-actuator-health"]
```

A name in `disabled` that is not a built-in decoy is a startup error, so a typo cannot
silently leave the decoy on.

## Decoys of your own

In TOML, appended to the built-in set:

```toml
[[detectors.decoy-path.decoys]]
id = "internal-backup"
description = "Fake internal backup endpoint"
path = "/internal/backup.sql"      # exact; or pattern = "^/internal/.*\\.sql$"
score = 9
respond_with = "large-payload"     # let them download 50 MB of nothing

[[detectors.decoy-path.decoys]]
id = "jenkins"
description = "Jenkins script console probe"
pattern = "^/(jenkins|script)(/.*)?$"
score = 8
respond_with = "decoy-content"
[detectors.decoy-path.decoys.payload]
status = 200
content_type = "text/html; charset=utf-8"
body = "<html><body><h1>Jenkins</h1></body></html>"
```

- `path` or `pattern`, one or the other. `score` defaults to 5.
- A custom decoy sharing an id with a built-in one takes precedence over it.
- `replace_defaults = true` uses only your decoys.
- `score` and `respond_with` are per decoy, so the `[detectors.decoy-path]` section itself
  does not accept them.

In code:

```ts
import { HoneypotEngine, decoyPathDetector, defaultDecoyPaths, type DecoyPath } from "@osqd/hackerpot";

const invoices: DecoyPath = {
  id: "invoice-export",
  description: "Bulk invoice export probe",
  path: "/api/invoices/export",
  match: "prefix",
  score: 8,
  respondWith: "fake-data",
};

new HoneypotEngine({
  detectors: [decoyPathDetector([...defaultDecoyPaths, invoices]) /* , …the rest of your set */],
});
```

Passing an array **replaces** the built-in decoys, so spread `defaultDecoyPaths` to keep them.
And because `detectors` replaces the whole set, include every other detector you want; the
simplest form is `defaultDetectors().map((d) => (d.id === "decoy-path" ? decoyPathDetector([...]) : d))`.

## Making a decoy convincing

A decoy works best when probing it appears to succeed:

- **`decoy-content`** with a realistic payload: a fake login page, a plausible JSON body.
- **`fake-data`** synthesises fresh fake secrets per hit: a `.env`, an AWS credentials file,
  a user table. Every response differs, so exfiltrated values are noise. Never seed it with
  real names or a domain you use; see [actions](../responses/actions.md#fake-data).
- **A honeytoken in the payload.** The built-in decoys' [seeded secrets](#seeded-secrets) already are
  honeytokens. For a decoy of your own, put a value in its payload and list it in
  `[detectors.honeytoken] tokens`. Whoever reads the file and later uses the key has proven
  what they are. See [honeytokens](traps-and-honeytokens.md#honeytokens).

## robots.txt as a lure

A `robots.txt` that lists the decoys as `Disallow` has two effects. A legitimate crawler
obeys it and never touches them, so your incidents are not cluttered with well-behaved bots.
Anything that fetches a disallowed path anyway has shown it does not respect robots.txt.

```bash
npx hackerpot robots --sitemap https://example.com/sitemap.xml > public/robots.txt
```

```
# Generated by hackerpot. The paths below are honeypot decoys advertised as
# Disallow: a legitimate crawler skips them, so anything that fetches one
# anyway has identified itself as not respecting robots.txt.
User-agent: *
Disallow: /.aws
Disallow: /.aws/credentials
…
```

The command reads your config: custom decoys are included, disabled ones left out, and trap
paths added when `[detectors.trap]` is enabled. Only string decoys can be listed; a pattern
has no single path to disallow.

In code:

```ts
import { generateRobotsTxt, DEFAULT_TRAP_PATHS } from "@osqd/hackerpot";

app.get("/robots.txt", (_req, res) =>
  res.type("text/plain").send(generateRobotsTxt({ trapPaths: DEFAULT_TRAP_PATHS, sitemap: "https://example.com/sitemap.xml" })),
);
```

`generateRobotsTxt({ decoys?, extraDisallow?, sitemap?, trapPaths? })` uses the built-in
decoys when `decoys` is omitted.

Advertising decoys also tells a curious reader where they are. That costs little: a decoy
works on automated tooling that probes a wordlist regardless, and a person reading your
robots.txt was never going to be caught by one.

## Related

- [Traps and honeytokens](traps-and-honeytokens.md) — decoys that are proof
- [Response actions](../responses/actions.md) — what a decoy can serve
- [nginx edge capture](../integration/nginx.md) — the same decoys, diverted at the edge
