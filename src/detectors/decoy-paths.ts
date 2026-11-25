import { createHash, randomBytes } from "node:crypto";
import { statelessPattern } from "../internal/pattern.js";
import type { Detection, DetectionContext, Detector } from "./types.js";

export interface DecoyPath {
  id: string;
  description: string;
  /** Exact path (trailing slash insensitive) or RegExp tested against the request path. */
  path: string | RegExp;
  /**
   * How a string `path` matches. `exact` (the default) matches only that path. `prefix`
   * also matches anything under it or with a suffix after a dot, so `/.env` covers
   * `/.env.local` and `/.env/`, and `/.git` covers `/.git/index`. It matches only at
   * a `/` or `.` boundary, so `/backup` does not match `/backup-your-data-a-guide`.
   * Prefix matching ignores case, since scanners probe both spellings and some servers
   * serve both. `anywhere` is `prefix` at any directory depth: `/.env` also covers
   * `/laravel/.env` and `/backup/.env.local`, which is where scanners look once the root
   * has been tried. Ignored for a RegExp path.
   */
  match?: "exact" | "prefix" | "anywhere";
  method?: string;
  score: number;
  /** Response action id to run when this decoy is hit. */
  respondWith?: string;
  /** Payload handed to the response action — e.g. the fake file body to serve. */
  payload?: { status?: number; contentType?: string; body?: string; location?: string };
}

/**
 * The secrets a set of built-in decoys hands out, derived from one seed.
 *
 * They used to be constants: AWS's documentation key `AKIAIOSFODNN7EXAMPLE` and a remote at
 * `github.com/example/example.git`, identical in every install. A scanner that has met one
 * HackerPot has met them all, and a well-known example key is the first thing a harvesting
 * tool learns to discard. Seeded, the values differ per install and stay the same across its
 * restarts, so a returning prober sees a consistent file, and every value is long and random
 * enough to work as a honeytoken (`decoySecrets`).
 *
 * Nothing here points at anybody else: the git remote is under `.internal`, a name reserved
 * never to resolve on the public internet, and the database host is the loopback address.
 */
export interface DecoySecrets {
  appKey: string;
  dbName: string;
  dbUser: string;
  dbPassword: string;
  awsAccessKeyId: string;
  awsSecretAccessKey: string;
  gitRemote: string;
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const PASSWORD_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+=";
const PROJECT_WORDS = ["portal", "shop", "billing", "core", "platform", "backend", "api", "crm", "dashboard", "payments", "orders", "accounts"];
const TEAM_WORDS = ["web", "ops", "infra", "product", "platform", "dev", "apps", "engineering"];

/** Deterministic bytes for one named value, so each field is independent of the others. */
function streamFor(seed: string, label: string, length: number): Buffer {
  const out: Buffer[] = [];
  let total = 0;
  for (let counter = 0; total < length; counter++) {
    const block = createHash("sha256").update(`hackerpot-decoy\0${seed}\0${label}\0${counter}`).digest();
    out.push(block);
    total += block.length;
  }
  return Buffer.concat(out).subarray(0, length);
}

function pick(seed: string, label: string, alphabet: string, length: number): string {
  return [...streamFor(seed, label, length)].map((byte) => alphabet[byte % alphabet.length]).join("");
}

function word(seed: string, label: string, words: readonly string[]): string {
  return words[streamFor(seed, label, 1)[0]! % words.length]!;
}

/** The decoy secrets for `seed`. The same seed always gives the same values. */
export function decoySecrets(seed: string): DecoySecrets {
  const project = word(seed, "project", PROJECT_WORDS);
  return {
    appKey: `base64:${streamFor(seed, "app-key", 32).toString("base64")}`,
    dbName: `${project}_prod`,
    dbUser: `${project}_app`,
    dbPassword: pick(seed, "db-password", PASSWORD_CHARS, 20),
    awsAccessKeyId: `AKIA${pick(seed, "aws-key-id", BASE32, 16)}`,
    awsSecretAccessKey: streamFor(seed, "aws-secret", 30).toString("base64"),
    gitRemote: `https://git.${word(seed, "team", TEAM_WORDS)}.internal/${project}/${project}-server.git`,
  };
}

/**
 * The planted values worth watching for, as honeytokens. Short or guessable ones (a database
 * name) are left out: a honeytoken must be something no legitimate request can contain.
 */
export function decoyHoneytokens(seed: string): Array<{ value: string; label: string }> {
  const secrets = decoySecrets(seed);
  return [
    { value: secrets.appKey, label: "decoy .env APP_KEY" },
    { value: secrets.dbPassword, label: "decoy .env DB_PASSWORD" },
    { value: secrets.awsAccessKeyId, label: "decoy AWS access key id" },
    { value: secrets.awsSecretAccessKey, label: "decoy AWS secret key" },
  ];
}

function fakeEnv(secrets: DecoySecrets): string {
  return [
    "APP_ENV=production",
    `APP_KEY=${secrets.appKey}`,
    "DB_HOST=127.0.0.1",
    `DB_DATABASE=${secrets.dbName}`,
    `DB_USERNAME=${secrets.dbUser}`,
    `DB_PASSWORD=${secrets.dbPassword}`,
    `AWS_ACCESS_KEY_ID=${secrets.awsAccessKeyId}`,
    `AWS_SECRET_ACCESS_KEY=${secrets.awsSecretAccessKey}`,
    "",
  ].join("\n");
}

const FAKE_LOGIN_HTML =
  "<!doctype html><html><head><title>Admin Login</title></head>" +
  "<body><h2>Administrator Login</h2>" +
  '<form method="post"><input name="username" placeholder="Username">' +
  '<input name="password" type="password" placeholder="Password">' +
  '<button type="submit">Log in</button></form></body></html>';

/**
 * Paths that scanners and opportunistic attackers probe for: secrets files,
 * admin/CMS panels, framework debug endpoints, and known RCE probe targets.
 * Nothing here replaces real access control — it is bait that reveals
 * automated recon before it reaches anything real.
 */
export function decoyPathsFor(seed: string): DecoyPath[] {
  const secrets = decoySecrets(seed);
  return [
  { id: "dotenv", description: "Exposed .env file probe", path: "/.env", match: "anywhere", score: 10, respondWith: "decoy-content", payload: { status: 200, contentType: "text/plain; charset=utf-8", body: fakeEnv(secrets) } },
  { id: "git-config", description: "Exposed .git directory probe", path: "/.git/config", match: "anywhere", score: 10, respondWith: "decoy-content", payload: { status: 200, contentType: "text/plain; charset=utf-8", body: `[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = ${secrets.gitRemote}\n` } },
  { id: "git-head", description: "Exposed .git HEAD probe", path: "/.git/HEAD", match: "anywhere", score: 8, respondWith: "decoy-content", payload: { status: 200, contentType: "text/plain; charset=utf-8", body: "ref: refs/heads/main\n" } },
  { id: "aws-credentials", description: "AWS credentials file probe", path: "/.aws/credentials", match: "anywhere", score: 10, respondWith: "decoy-content", payload: { status: 200, contentType: "text/plain; charset=utf-8", body: `[default]\naws_access_key_id = ${secrets.awsAccessKeyId}\naws_secret_access_key = ${secrets.awsSecretAccessKey}\n` } },
  { id: "ssh-key", description: "SSH private key probe", path: "/.ssh/id_rsa", match: "anywhere", score: 10, respondWith: "not-found" },
  { id: "docker-config", description: "Docker registry credentials probe", path: "/.docker/config.json", match: "anywhere", score: 8, respondWith: "not-found" },
  { id: "git-dir", description: "Exposed .git directory probe", path: "/.git", match: "anywhere", score: 9, respondWith: "not-found" },
  { id: "aws-dir", description: "AWS CLI configuration probe", path: "/.aws", match: "anywhere", score: 9, respondWith: "not-found" },
  { id: "ssh-dir", description: "SSH directory probe", path: "/.ssh", match: "anywhere", score: 9, respondWith: "not-found" },
  { id: "package-credentials", description: "Package registry credentials probe (.npmrc, .pypirc, .netrc)", path: /(?:^|\/)\.(npmrc|pypirc|netrc|git-credentials)$/i, score: 8, respondWith: "not-found" },
  { id: "htpasswd", description: "Apache password file probe", path: "/.htpasswd", match: "anywhere", score: 8, respondWith: "not-found" },
  { id: "shell-history", description: "Shell history probe", path: /(?:^|\/)\.(bash|zsh|sh|mysql|psql)_history$/i, score: 7, respondWith: "not-found" },

  { id: "wp-login", description: "WordPress login probe", path: "/wp-login.php", score: 5, respondWith: "decoy-content", payload: { status: 200, contentType: "text/html; charset=utf-8", body: FAKE_LOGIN_HTML } },
  { id: "wp-admin", description: "WordPress admin probe", path: /^\/wp-admin(\/.*)?$/, score: 5, respondWith: "redirect", payload: { status: 302, location: "/wp-login.php" } },
  { id: "xmlrpc", description: "WordPress XML-RPC probe (brute-force/amplification target)", path: "/xmlrpc.php", score: 6, respondWith: "decoy-content", payload: { status: 405, contentType: "text/plain; charset=utf-8", body: "XML-RPC server accepts POST requests only." } },
  { id: "phpmyadmin", description: "phpMyAdmin panel probe", path: /^\/(phpmyadmin|pma|adminer\.php)(\/.*)?$/i, score: 6, respondWith: "decoy-content", payload: { status: 200, contentType: "text/html; charset=utf-8", body: FAKE_LOGIN_HTML } },
  { id: "admin-panel", description: "Generic admin panel probe", path: /^\/(admin|administrator)(\/login)?$/i, score: 4, respondWith: "decoy-content", payload: { status: 200, contentType: "text/html; charset=utf-8", body: FAKE_LOGIN_HTML } },

  { id: "spring-actuator-env", description: "Spring Boot Actuator env dump probe", path: "/actuator/env", match: "prefix", score: 8, respondWith: "decoy-content", payload: { status: 200, contentType: "application/json", body: JSON.stringify({ profiles: ["default"] }) } },
  { id: "spring-actuator-health", description: "Spring Boot Actuator probe", path: "/actuator/health", score: 3, respondWith: "decoy-content", payload: { status: 200, contentType: "application/json", body: JSON.stringify({ status: "UP" }) } },
  { id: "spring-actuator-heapdump", description: "Spring Boot Actuator heap dump probe (memory holds live secrets)", path: "/actuator/heapdump", score: 9, respondWith: "not-found" },
  { id: "spring-cloud-gateway-rce", description: "Spring Cloud Gateway route-injection RCE probe (CVE-2022-22947)", path: "/actuator/gateway/routes", match: "prefix", score: 9, respondWith: "not-found" },
  { id: "server-status", description: "Apache mod_status probe", path: "/server-status", score: 5, respondWith: "decoy-content", payload: { status: 403, contentType: "text/plain; charset=utf-8", body: "Forbidden" } },
  { id: "go-pprof", description: "Go net/http/pprof debug endpoint probe", path: /^\/debug\/pprof(\/.*)?$/, score: 7, respondWith: "not-found" },
  { id: "laravel-telescope", description: "Laravel Telescope debug dashboard probe", path: /^\/telescope(\/.*)?$/, score: 6, respondWith: "not-found" },
  { id: "laravel-ignition-rce", description: "Laravel Ignition file-execution RCE probe (CVE-2021-3129)", path: "/_ignition/execute-solution", match: "prefix", score: 10, respondWith: "not-found" },
  { id: "phpunit-eval-rce", description: "PHPUnit eval-stdin.php RCE probe", path: "/vendor/phpunit", match: "prefix", score: 10, respondWith: "not-found" },
  { id: "php-info", description: "phpinfo() page probe", path: "/phpinfo.php", score: 5, respondWith: "not-found" },
  { id: "wp-config", description: "WordPress configuration source probe", path: "/wp-config.php", match: "anywhere", score: 7, respondWith: "not-found" },
  { id: "couchdb-all-dbs", description: "CouchDB database listing probe", path: "/_all_dbs", score: 7, respondWith: "not-found" },
  { id: "solr-admin", description: "Apache Solr admin API probe", path: "/solr/admin", match: "prefix", score: 7, respondWith: "not-found" },
  { id: "tomcat-manager", description: "Tomcat manager console probe", path: "/manager/html", match: "prefix", score: 7, respondWith: "not-found" },
  { id: "jenkins-script-console", description: "Jenkins Groovy script console probe", path: "/jenkins/script", match: "prefix", score: 8, respondWith: "not-found" },
  { id: "druid-indexer", description: "Apache Druid indexer RCE probe", path: "/druid/indexer", match: "prefix", score: 8, respondWith: "not-found" },
  { id: "geoserver", description: "GeoServer web console probe", path: "/geoserver/web", match: "prefix", score: 7, respondWith: "not-found" },
  { id: "router-rce", description: "Consumer router/IoT exploit probe (boaform, LuCI, HNAP)", path: /^\/(boaform|cgi-bin\/luci|hnap1)(\/.*)?$/i, score: 8, respondWith: "not-found" },
  { id: "fortinet-traversal", description: "Fortinet SSL-VPN path traversal probe (CVE-2018-13379)", path: "/remote/fgt_lang", match: "prefix", score: 9, respondWith: "not-found" },
  { id: "yii-debug", description: "Yii debug toolbar probe", path: "/debug/default/view", match: "prefix", score: 7, respondWith: "not-found" },

  { id: "swagger", description: "Swagger/OpenAPI spec probe", path: /^\/(swagger(-ui)?|api-docs|openapi)(\.json)?$/i, score: 3, respondWith: "not-found" },
  { id: "backup-archive", description: "Backup/dump archive probe", path: /^\/(backup|db|dump)\.(zip|sql|tar\.gz|tgz)$/i, score: 7, respondWith: "not-found" },
  { id: "config-file", description: "Generic config file probe", path: /^\/config\.(json|php|yml|yaml)$/i, score: 5, respondWith: "not-found" },
  ];
}

/**
 * The seed this process uses when the configuration names none: random per start, so no two
 * installs serve the same file. Set `[detectors.decoy-path] seed` to keep the values stable
 * across restarts, which is what makes a returning prober see a consistent target.
 */
export const DEFAULT_DECOY_SEED: string = randomBytes(16).toString("hex");

/** The built-in decoys, seeded with this process's `DEFAULT_DECOY_SEED`. */
export const defaultDecoyPaths: DecoyPath[] = decoyPathsFor(DEFAULT_DECOY_SEED);

function normalize(path: string): string {
  return path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
}

/**
 * Whether `path` is `entry`, or lies under it at a `/` or `.` boundary. A plain
 * `startsWith` would make `/backup` match `/backup-your-data-a-guide`, an article. From
 * bothandlerjs's probe-signature detector.
 */
function underPrefix(path: string, entry: string): boolean {
  const lowerPath = path.toLowerCase();
  const lowerEntry = normalize(entry).toLowerCase();
  if (!lowerPath.startsWith(lowerEntry)) return false;
  if (lowerPath.length === lowerEntry.length) return true;
  const next = lowerPath.charCodeAt(lowerEntry.length);
  return next === 0x2f /* / */ || next === 0x2e /* . */;
}

/** `underPrefix` at the root or below any directory: `/.env` matches `/app/.env.local`. */
function underPrefixAnywhere(path: string, entry: string): boolean {
  for (let slash = path.indexOf("/"); slash !== -1; slash = path.indexOf("/", slash + 1)) {
    if (underPrefix(path.slice(slash), entry)) return true;
  }
  return false;
}

function matches(decoy: DecoyPath, method: string, path: string): boolean {
  const wanted = decoy.method ?? "*";
  if (wanted !== "*" && wanted.toUpperCase() !== method.toUpperCase()) return false;
  if (typeof decoy.path === "string") {
    if (decoy.match === "anywhere") return underPrefixAnywhere(path, decoy.path);
    return decoy.match === "prefix" ? underPrefix(path, decoy.path) : normalize(decoy.path) === normalize(path);
  }
  return decoy.path.test(path);
}

/** Fires when a request hits one of the decoy paths — the highest-confidence signal the honeypot has. */
export function decoyPathDetector(decoys: DecoyPath[] = defaultDecoyPaths): Detector {
  // A `g`/`y` regex decoy would match on every other request. See `statelessPattern`.
  const safe = decoys.map((decoy) => (typeof decoy.path === "string" ? decoy : { ...decoy, path: statelessPattern(decoy.path) }));
  return {
    id: "decoy-path",
    description: "Request targeted a decoy path that no legitimate client would know about",
    inspect(ctx: DetectionContext): Detection | undefined {
      const decoy = safe.find((candidate) => matches(candidate, ctx.method, ctx.path));
      if (!decoy) return undefined;
      const detection: Detection = {
        detector: "decoy-path",
        summary: decoy.description,
        score: decoy.score,
        metadata: { decoyId: decoy.id, payload: decoy.payload },
      };
      if (decoy.respondWith) detection.respondWith = decoy.respondWith;
      return detection;
    },
  };
}
