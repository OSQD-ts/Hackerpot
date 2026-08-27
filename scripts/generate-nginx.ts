import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  defaultDecoyPaths,
  scannerUserAgentPatterns,
  defaultSuspiciousMethods,
  injectionSignatures,
  sensitiveFilePatterns,
} from "../src/index.js";

/**
 * Emits ready-to-`include` nginx config that catches, at the edge, the suspicious
 * requests the honeypot can recognize *statically* — decoy paths, scanner
 * User-Agents, suspicious HTTP methods, and (best-effort) injection payloads in
 * the URI — and reverse-proxies them to the honeypot upstream so they never touch
 * the real backend. The client-facing response is served by the honeypot, so the
 * attacker cannot tell they were diverted.
 *
 * nginx `include` is a verbatim textual splice, so the output is split by the
 * context each half must live in — one file for `http {}`, one for `server {}`:
 *
 *   hackerpot-http.conf         -> /etc/nginx/conf.d/          (loaded once)
 *   hackerpot-server.conf       -> /etc/nginx/snippets/        (included per vhost)
 *   hackerpot-site.conf.example -> /etc/nginx/sites-available/ (worked example)
 *
 * Out of scope for a static config (they need per-IP state nginx does not keep
 * here, or run below HTTP): path/credential brute-force, rate spikes, and the
 * TCP port-scan sentinel. Keep the honeypot itself running for those.
 */

const HTTP_FILE = "hackerpot-http.conf";
const SERVER_FILE = "hackerpot-server.conf";
const SITE_FILE = "hackerpot-site.conf.example";

/** Status code used purely as an internal marker between the server-level guard
 *  and the named location. Never reaches the client. */
const DIVERT_CODE = 418;

interface Options {
  upstream: string;
  appUpstream: string;
  serverName: string;
  outDir: string | undefined;
  prefix: string;
  includeInjection: boolean;
}

const USAGE = `Usage: npm run generate:nginx -- [options]

  --upstream <host:port>      honeypot upstream            (default 127.0.0.1:4004)
  --app-upstream <host:port>  your real app, for the example vhost (default 127.0.0.1:3000)
  --server-name <name>        server_name for the example vhost    (default example.com)
  --out-dir <dir>             where to write the files             (default nginx)
  --prefix <dir>              nginx config root, for the printed instructions (default /etc/nginx)
  --stdout                    print all files instead of writing them
  --no-injection              skip the best-effort URI-injection map
  --help                      show this
`;

function parseArgs(argv: string[]): Options {
  const opts: Options = {
    upstream: "127.0.0.1:4004",
    appUpstream: "127.0.0.1:3000",
    serverName: "example.com",
    outDir: "nginx",
    prefix: "/etc/nginx",
    includeInjection: true,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--upstream") opts.upstream = argv[++i] ?? opts.upstream;
    else if (arg === "--app-upstream") opts.appUpstream = argv[++i] ?? opts.appUpstream;
    else if (arg === "--server-name") opts.serverName = argv[++i] ?? opts.serverName;
    else if (arg === "--out-dir") opts.outDir = argv[++i] ?? opts.outDir;
    else if (arg === "--prefix") opts.prefix = (argv[++i] ?? opts.prefix).replace(/\/+$/, "");
    else if (arg === "--stdout") opts.outDir = undefined;
    else if (arg === "--no-injection") opts.includeInjection = false;
    else if (arg === "--help" || arg === "-h") {
      process.stdout.write(USAGE);
      process.exit(0);
    } else if (arg === "--out") {
      console.error(
        `--out is gone: the config is now several files, one per nginx context. Use --out-dir <dir>.\n`,
      );
      process.exit(1);
    } else {
      console.error(`Unknown option: ${arg}\n\n${USAGE}`);
      process.exit(1);
    }
  }
  return opts;
}

/**
 * nginx's config parser applies its own escape processing inside quoted strings:
 * `\\` collapses to `\`, `\"` to `"`. A regex pasted in raw therefore reaches PCRE
 * mangled — `[/\\]` arrives as `[/\]`, an unterminated class that silently swallows
 * whatever follows. Double every backslash so PCRE receives what was written.
 */
function forNginxString(source: string): string {
  return source.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/** JS RegExp source → an nginx-safe, double-quoted regex literal (for `location ~`). */
function toNginxRegex(source: string): string {
  return `"${forNginxString(source)}"`;
}

/** A quoted, case-insensitive nginx map key. Quoting the whole `~*…` is required
 *  because some patterns contain spaces (e.g. "nette tester"), which would
 *  otherwise be mis-tokenized by nginx. */
function toNginxMapKey(source: string): string {
  return `"~*${forNginxString(source)}"`;
}

/**
 * nginx only ever sees `$request_uri` raw — it has no urldecode. A signature
 * written against decoded text (what the honeypot's own detectors receive)
 * therefore never fires on the form real tooling sends: `union%20select`,
 * `%3Cscript`, `1%27%20or%201%3D1`. This rewrites a pattern so every literal it
 * matches is also accepted in percent-encoded form.
 *
 * Only the URI-injection map needs this. `$http_user_agent` is not encoded, and
 * `$uri` has already been decoded and normalized by nginx.
 */
const PERCENT_FORMS: Record<string, string[]> = {
  " ": ["%20", "%09", "%0a", "%0d", "\\+"],
  "<": ["%3c"], ">": ["%3e"],
  '"': ["%22"], "'": ["%27"],
  "(": ["%28"], ")": ["%29"],
  "{": ["%7b"], "}": ["%7d"],
  ";": ["%3b"], ":": ["%3a"],
  "|": ["%7c"], "`": ["%60"],
  "$": ["%24"], "=": ["%3d"],
  "/": ["%2f"], "\\": ["%5c"],
  "*": ["%2a"], "?": ["%3f"],
  "!": ["%21"], ".": ["%2e"],
  ",": ["%2c"], "&": ["%26"],
  "#": ["%23"], "@": ["%40"],
};

const WHITESPACE_FORMS = PERCENT_FORMS[" "]!;

/** Regex metacharacters, which are only literals when backslash-escaped. */
const REGEX_META = new Set(["\\", "^", "$", ".", "|", "?", "*", "+", "(", ")", "[", "]", "{", "}"]);

/**
 * `\b` fails across an encoded separator — in `union%20select` the "0" and "s"
 * are both word characters, so there is no boundary before `select`. Widen it to
 * also accept a percent-escape on either side, which keeps the anchor honest
 * (`reunion` still will not match `\bunion`) without losing encoded payloads.
 */
const WORD_BOUNDARY = "(?:\\b|(?<=%[0-9a-f]{2})|(?=%[0-9a-f]{2}))";

function literalAtom(ch: string): string {
  return REGEX_META.has(ch) ? `\\${ch}` : ch;
}

function expandLiteral(ch: string): string {
  const forms = PERCENT_FORMS[ch];
  if (!forms) return literalAtom(ch);
  return `(?:${[literalAtom(ch), ...forms].join("|")})`;
}

/** Index of the `]` closing the character class that starts at `start`. */
function classEnd(source: string, start: number): number {
  let i = start + 1;
  if (source[i] === "^") i++;
  if (source[i] === "]") i++; // a leading ] is a literal
  for (; i < source.length; i++) {
    if (source[i] === "\\") i++;
    else if (source[i] === "]") return i;
  }
  return source.length - 1;
}

/** `[\s/*]` -> `(?:[\s/*]|%20|%09|…|%2f|%2a)`. Negated classes already match `%`. */
function expandClass(body: string): string {
  const inner = body.slice(1, -1);
  if (inner.startsWith("^")) return body;
  const extra = new Set<string>();
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (ch === "\\") {
      const next = inner[++i];
      if (next === "s") for (const form of WHITESPACE_FORMS) extra.add(form);
      else for (const form of PERCENT_FORMS[next] ?? []) extra.add(form);
      continue;
    }
    for (const form of PERCENT_FORMS[ch] ?? []) extra.add(form);
  }
  if (extra.size === 0) return body;
  return `(?:${body}|${[...extra].join("|")})`;
}

function percentTolerant(source: string): string {
  let out = "";
  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (ch === "\\") {
      const next = source[++i];
      if (next === "s") out += `(?:\\s|${WHITESPACE_FORMS.join("|")})`;
      else if (next === "b") out += WORD_BOUNDARY;
      else if (next !== undefined && PERCENT_FORMS[next]) out += expandLiteral(next);
      else out += `\\${next ?? ""}`;
      continue;
    }
    if (ch === "[") {
      const end = classEnd(source, i);
      out += expandClass(source.slice(i, end + 1));
      i = end;
      continue;
    }
    if (ch === "{") {
      // A {n}/{n,}/{n,m} quantifier is structure, not text: its comma must survive.
      const quantifier = /^\{\d+(?:,\d*)?\}/.exec(source.slice(i));
      if (quantifier) {
        out += quantifier[0];
        i += quantifier[0].length - 1;
        continue;
      }
    }
    if (ch === "(") {
      // Group-opening syntax is structure, not text. `:` is not a regex metacharacter,
      // so without this the `:` inside `(?:` was percent-expanded and the group opener
      // became `(?` + `(?::|%3a)` — which PCRE reads as a conditional group `(?(...)`
      // and refuses to compile, so **nginx fails to start**. The same applies to the
      // lookaround and named-group forms. This held only by luck for a long time: no
      // signature happened to contain `(?:`, so the first one to use a non-capturing
      // group silently produced an unloadable config.
      const group = /^\((?:\?(?:<[A-Za-z_$][A-Za-z0-9_$]*>|<=|<!|:|=|!))?/.exec(source.slice(i));
      if (group) {
        out += group[0];
        i += group[0].length - 1;
        continue;
      }
    }
    out += REGEX_META.has(ch) ? ch : expandLiteral(ch);
  }
  return out;
}

/**
 * Merge several JS RegExps into one case-insensitive nginx alternation.
 *
 * The result is compiled before it is returned. The transform rewrites patterns
 * character by character with no real grammar, so a signature using a construct it
 * mishandles yields a regex that is subtly invalid — and the only symptom is nginx
 * refusing to start at `nginx -t`, on the operator's box, at deploy time. Failing here
 * turns that into a build error next to the code that caused it.
 */
function mergePatterns(patterns: RegExp[], transform: (source: string) => string = (x) => x): string {
  const merged = patterns.map((pattern) => `(?:${transform(pattern.source)})`).join("|");
  try {
    new RegExp(merged);
  } catch (err) {
    throw new Error(
      `generated an invalid regex (nginx would refuse to load it): ${(err as Error).message}\n` +
        `from: ${patterns.map((p) => p.source).join("  ||  ")}`,
    );
  }
  return merged;
}

function banner(text: string): string {
  return `# ${"=".repeat(74)}\n# ${text}\n# ${"=".repeat(74)}`;
}

/** Every generated file opens with a banner, a do-not-edit line, and an
 *  install/include note — the file explains its own wiring. */
function fileHeader(title: string, notes: string[]): string {
  return [
    banner(`hackerpot — ${title}`),
    "# GENERATED by `npm run generate:nginx` — do not edit by hand; regenerate instead.",
    "#",
    ...notes.map((line) => (line ? `# ${line}` : "#")),
    banner("").split("\n")[0],
  ].join("\n");
}

// ---------------------------------------------------------------------------
// http {} context — upstream + maps
// ---------------------------------------------------------------------------

function buildHttpFile(opts: Options): string {
  const p = opts.prefix;
  const lines: string[] = [];
  lines.push(
    fileHeader("http-context config (upstream + classification maps)", [
      `WHERE THIS GOES: the http {} block — exactly once per nginx instance.`,
      "",
      `    sudo cp ${HTTP_FILE} ${p}/conf.d/`,
      "",
      `${p}/nginx.conf already has \`include ${p}/conf.d/*.conf;\` inside http {},`,
      "so nothing in nginx.conf needs editing.",
      "",
      "Do NOT include this from a sites-enabled vhost: two vhosts including it would",
      "define `upstream hackerpot_backend` twice and nginx would refuse to start with",
      '"duplicate upstream". One copy in conf.d/ serves every vhost on the box.',
      "",
      `Pairs with ${SERVER_FILE}, included inside each server {} you want protected.`,
    ]),
  );
  lines.push("");
  lines.push(`upstream hackerpot_backend {`);
  lines.push(`    server ${opts.upstream};`);
  lines.push(`    keepalive 16;`);
  lines.push(`}`);
  lines.push("");

  lines.push("# Scanner / exploitation-tool User-Agents (and bare scripting clients).");
  lines.push("#");
  lines.push("# CAVEAT: this matches the CLIENT, not the request — it includes curl/, wget/,");
  lines.push("# python-requests and go-http-client. If you run a public API, every legitimate");
  lines.push("# client using those is diverted on EVERY path. Trim the list if your API is");
  lines.push("# meant to be scripted against.");
  lines.push("map $http_user_agent $hp_bad_ua {");
  lines.push("    default 0;");
  lines.push(`    ${toNginxMapKey(mergePatterns(scannerUserAgentPatterns))} 1;`);
  lines.push("}");
  lines.push("");

  lines.push("# HTTP verbs no browser or normal API client sends.");
  lines.push("map $request_method $hp_bad_method {");
  lines.push("    default 0;");
  for (const method of defaultSuspiciousMethods) lines.push(`    ${method} 1;`);
  lines.push("}");
  lines.push("");

  lines.push("# Risky file types (backup/dump/source/VCS/IDE) requested anywhere.");
  lines.push("#");
  lines.push("# CAVEAT: this matches on EXTENSION ALONE, with no regard for how legitimate the");
  lines.push("# client is. If your site serves .zip/.tar.gz release archives, .sql exports or");
  lines.push("# .log downloads, those requests are diverted to the honeypot instead of reaching");
  lines.push("# your app — from real browsers, with real sessions. Check your access log before");
  lines.push("# enabling, and delete the offending alternative if it collides with real traffic.");
  lines.push("map $uri $hp_bad_file {");
  lines.push("    default 0;");
  lines.push(`    ${toNginxMapKey(mergePatterns(sensitiveFilePatterns))} 1;`);
  lines.push("}");
  lines.push("");

  if (opts.includeInjection) {
    lines.push("# Best-effort: injection payloads visible in the raw request URI. The signatures");
    lines.push("# are widened to also match percent-encoded payloads, since nginx has no urldecode");
    lines.push("# and real tooling sends `union%20select`, not `union select`.");
    lines.push("# Bodies and headers stay out of reach here — the honeypot still covers those.");
    lines.push("map $request_uri $hp_bad_uri {");
    lines.push("    default 0;");
    lines.push(`    ${toNginxMapKey(mergePatterns(injectionSignatures.map((s) => s.pattern), percentTolerant))} 1;`);
    lines.push("}");
    lines.push("");
  }

  const flagInputs = opts.includeInjection
    ? "$hp_bad_ua$hp_bad_method$hp_bad_file$hp_bad_uri"
    : "$hp_bad_ua$hp_bad_method$hp_bad_file";
  const allZero = opts.includeInjection ? "0000" : "000";
  lines.push("# Combined edge flag: 1 if any of the above matched, else 0.");
  lines.push(`map "${flagInputs}" $hp_flagged {`);
  lines.push("    default 1;");
  lines.push(`    "${allZero}" 0;`);
  lines.push("}");
  return lines.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// server {} context — guard + decoy locations
// ---------------------------------------------------------------------------

function decoyLocations(path: string | RegExp, id: string, method: string | undefined): string[] {
  const note = `  # ${id}${method && method !== "*" ? ` (${method})` : ""}`;
  const body = `{ return ${DIVERT_CODE}; }`;
  if (typeof path === "string") {
    // The honeypot matches decoy paths trailing-slash-insensitively; `location =`
    // does not, so emit both forms to keep the edge in step with the detector.
    const bare = path.replace(/\/+$/, "");
    const forms = bare === "" ? [path] : [bare, `${bare}/`];
    return forms.map((form) => `location = ${form} ${body}${note}`);
  }
  const op = path.flags.includes("i") ? "~*" : "~";
  return [`location ${op} ${toNginxRegex(path.source)} ${body}${note}`];
}

function buildServerFile(opts: Options): string {
  const p = opts.prefix;
  const lines: string[] = [];
  lines.push(
    fileHeader("server-context config (include inside server {})", [
      "WHERE THIS GOES: inside every server {} block you want protected — one line.",
      "",
      `    sudo cp ${SERVER_FILE} ${p}/snippets/            # Debian/Ubuntu`,
      `    sudo cp ${SERVER_FILE} ${p}/conf.d/hackerpot-server.inc   # RHEL/Alpine, see below`,
      "",
      `then in ${p}/sites-available/<yoursite>:`,
      "",
      "    server {",
      "        listen 443 ssl;",
      `        server_name ${opts.serverName};`,
      "",
      "        include snippets/hackerpot-server.conf;   # <-- anywhere inside server {}",
      "",
      `        location / { proxy_pass http://${opts.appUpstream}; }`,
      "    }",
      "",
      `    sudo ln -s ../sites-available/<yoursite> ${p}/sites-enabled/`,
      "    sudo nginx -t && sudo systemctl reload nginx",
      "",
      "Include paths are relative to the nginx prefix, so `snippets/…` resolves to",
      `${p}/snippets/…`,
      "",
      `On RHEL/Alpine there is no sites-enabled and ${p}/conf.d/*.conf is auto-included`,
      "at http level — a server-context file there would be a syntax error. Give it a",
      "non-.conf suffix (.inc) so only your explicit include picks it up.",
      "",
      "Nothing here sets proxy_* at server level, so your own location blocks are",
      "untouched: every diverted request is handled by the one @hackerpot location.",
      "",
      `REQUIRES ${HTTP_FILE} loaded in the http context (it defines the upstream and`,
      "the $hp_flagged variable this file reads).",
    ]),
  );
  lines.push("");

  lines.push("# --- How a diversion happens ---------------------------------------------");
  lines.push(`# Everything below funnels into @hackerpot by returning ${DIVERT_CODE}, which error_page`);
  lines.push("# turns into an internal redirect. `return` is the one construct that is always");
  lines.push('# safe inside `if` (nginx\'s "If Is Evil"), and the status never reaches the client.');
  lines.push("#");
  lines.push("# 405 is in the list because nginx rejects TRACE and CONNECT itself, during");
  lines.push("# request-line parsing, before any of this config runs — without it those two");
  lines.push("# verbs would get a stock 405 and the honeypot would never see them. Only");
  lines.push("# nginx-generated 405s are caught; a 405 from your proxied app passes through");
  lines.push("# untouched (proxy_intercept_errors is off by default). If this vhost serves");
  lines.push("# static files, note that nginx answers POST to a static file with 405 too.");
  lines.push(`error_page 405 ${DIVERT_CODE} = @hackerpot;`);
  lines.push("");

  lines.push("# --- Behavioral edge match: bad UA / method / file / URI on any path ------");
  lines.push("# Runs in the server rewrite phase, before a location is chosen, so it covers");
  lines.push("# the whole vhost without touching any of your location blocks.");
  lines.push("if ($hp_flagged) {");
  lines.push(`    return ${DIVERT_CODE};`);
  lines.push("}");
  lines.push("");

  lines.push("# --- The single place that talks to the honeypot --------------------------");
  lines.push("location @hackerpot {");
  lines.push("    # proxy_pass without a URI part passes the request line through untouched,");
  lines.push("    # so the honeypot sees the original raw path and query for its own detectors.");
  lines.push("    proxy_pass http://hackerpot_backend;");
  lines.push("");
  lines.push("    # Required for the upstream's `keepalive` to do anything: keepalive needs");
  lines.push("    # HTTP/1.1 and a cleared Connection header, or every probe costs a new");
  lines.push("    # connection — and probes arrive in floods.");
  lines.push("    proxy_http_version 1.1;");
  lines.push('    proxy_set_header Connection "";');
  lines.push("");
  lines.push("    # Real client identity, so the honeypot's trust_proxy attributes the attack.");
  lines.push("    #");
  lines.push("    # X-Forwarded-For is set to $remote_addr — the peer that actually connected to");
  lines.push("    # nginx — and NOT $proxy_add_x_forwarded_for, which APPENDS to whatever header");
  lines.push("    # the client sent. hackerpot reads the leftmost value, so appending would leave");
  lines.push("    # that value attacker-chosen: a probe carrying its own `X-Forwarded-For: <ip>`");
  lines.push("    # would arrive as `<ip>, <real client>` and be attributed to <ip>. That is a");
  lines.push("    # detection bypass (name an allowlisted address), a way to shed an accrued");
  lines.push("    # suspicion score, and — with [blocklist.enforcer] on — a way to have an");
  lines.push("    # arbitrary victim firewalled. Overwriting makes the header say only what nginx");
  lines.push("    # observed. The upstream chain is worthless to a honeypot anyway; it wants the");
  lines.push("    # peer. (Behind a CDN/load balancer, set this to the real-client variable that");
  lines.push("    # trusted edge gives you — e.g. $http_cf_connecting_ip — never the raw client");
  lines.push("    # header.)");
  lines.push("    proxy_set_header Host              $host;");
  lines.push("    proxy_set_header X-Real-IP         $remote_addr;");
  lines.push("    proxy_set_header X-Forwarded-For   $remote_addr;");
  lines.push("    proxy_set_header X-Forwarded-Proto $scheme;");
  lines.push("}");
  lines.push("");

  lines.push("# --- Decoy paths: a hit is a hit regardless of how well-behaved the client looks ---");
  const exact = defaultDecoyPaths.filter((d) => typeof d.path === "string");
  const regex = defaultDecoyPaths.filter((d) => typeof d.path !== "string");
  for (const decoy of exact) lines.push(...decoyLocations(decoy.path, decoy.id, decoy.method));
  lines.push("");
  lines.push("# Regex decoys — lower priority than the exact matches above, higher than any");
  lines.push("# prefix location in your vhost, so keep an eye out for overlaps with your app.");
  for (const decoy of regex) lines.push(...decoyLocations(decoy.path, decoy.id, decoy.method));
  return lines.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// A complete worked vhost, so there is something to copy rather than assemble
// ---------------------------------------------------------------------------

function buildSiteFile(opts: Options): string {
  const p = opts.prefix;
  return (
    fileHeader("example sites-enabled vhost", [
      "A worked example of the two includes in place. Not loaded by anything as-is —",
      "copy it, edit it, then enable it:",
      "",
      `    sudo cp ${SITE_FILE} ${p}/sites-available/${opts.serverName}`,
      `    sudo ln -s ../sites-available/${opts.serverName} ${p}/sites-enabled/`,
      "    sudo nginx -t && sudo systemctl reload nginx",
      "",
      `Assumes ${HTTP_FILE} is in ${p}/conf.d/ and ${SERVER_FILE} in ${p}/snippets/.`,
    ]) +
    `
server {
    listen 80;
    listen [::]:80;
    server_name ${opts.serverName};

    # hackerpot edge capture. One line; everything it needs (the upstream and the
    # $hp_flagged variable) comes from conf.d/${HTTP_FILE}.
    include snippets/${SERVER_FILE};

    # Your app. Requests that hackerpot flagged never reach it — the server-level
    # guard in the snippet diverts them before this location is selected.
    location / {
        proxy_pass http://${opts.appUpstream};
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`
  );
}

// ---------------------------------------------------------------------------

interface Emitted {
  name: string;
  content: string;
}

function build(opts: Options): Emitted[] {
  return [
    { name: HTTP_FILE, content: buildHttpFile(opts) },
    { name: SERVER_FILE, content: buildServerFile(opts) },
    { name: SITE_FILE, content: buildSiteFile(opts) },
  ];
}

function printInstructions(opts: Options, dir: string): void {
  const p = opts.prefix;
  console.log(`
Install (Debian/Ubuntu):

  1. http context, once per host:
       sudo cp ${join(dir, HTTP_FILE)} ${p}/conf.d/

  2. server context, once per protected vhost:
       sudo cp ${join(dir, SERVER_FILE)} ${p}/snippets/
       # then add this line inside the server {} block in ${p}/sites-available/<yoursite>:
       include snippets/${SERVER_FILE};

  3. Check and reload:
       sudo nginx -t && sudo systemctl reload nginx

  ${join(dir, SITE_FILE)} is a complete vhost with both includes already wired in.

RHEL/Alpine have no sites-enabled: step 1 is the same, but rename the server file to
hackerpot-server.inc so ${p}/conf.d/*.conf does not load it at http level, and include
it from your own server {} block.
`);
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const files = build(opts);

  if (!opts.outDir) {
    for (const file of files) {
      process.stdout.write(`${banner(`FILE: ${file.name}`)}\n${file.content}\n`);
    }
    return;
  }

  const dir = opts.outDir;
  await mkdir(dir, { recursive: true });
  for (const file of files) await writeFile(join(dir, file.name), file.content, "utf8");

  console.log(`Wrote ${files.length} files to ${dir}/`);
  for (const file of files) console.log(`  ${file.name}`);
  console.log(`
  upstream:          ${opts.upstream}
  decoy locations:   ${defaultDecoyPaths.length} decoys
  scanner UA rules:  ${scannerUserAgentPatterns.length} patterns
  method rules:      ${defaultSuspiciousMethods.length} verbs
  URI injection map: ${opts.includeInjection ? `${injectionSignatures.length} signatures (best-effort)` : "disabled"}`);
  printInstructions(opts, dir);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
