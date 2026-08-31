import http from "node:http";
import net from "node:net";
import { gunzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { Client } from "ssh2";
import {
  HoneypotEngine,
  HoneypotServer,
  MemoryStore,
  ssrfProbeDetector,
  openRedirectDetector,
  crlfInjectionDetector,
  webShellDetector,
  nosqlInjectionDetector,
  graphqlAbuseDetector,
  jwtWeaknessDetector,
  clientAnomalyDetector,
  prototypePollutionDetector,
  insecureDeserializationDetector,
  hostHeaderInjectionDetector,
  SmtpHoneypot,
  SshHoneypot,
} from "../src/index.js";
import type { HoneypotHit, RequestFacts } from "../src/index.js";

function facts(partial: Partial<RequestFacts> & Pick<RequestFacts, "path">): RequestFacts {
  return { method: "GET", query: {}, headers: {}, ip: "203.0.113.9", ...partial };
}

function raw(port: number, path: string, headers: Record<string, string> = {}): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ port, path, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("new detectors", () => {
  it("ssrf-probe flags an internal/metadata target", async () => {
    const engine = new HoneypotEngine({ detectors: [ssrfProbeDetector()] });
    const meta = await engine.evaluate(facts({ path: "/fetch", query: { url: "http://169.254.169.254/latest/meta-data/" } }));
    expect(meta.detections[0]?.detectorId).toBe("ssrf-probe");
    const file = await engine.evaluate(facts({ path: "/img", query: { src: "file:///etc/passwd" }, ip: "203.0.113.10" }));
    expect(file.detections[0]?.detectorId).toBe("ssrf-probe");
    const ok = await engine.evaluate(facts({ path: "/fetch", query: { url: "https://example.com/logo.png" }, ip: "203.0.113.11" }));
    expect(ok.detections).toHaveLength(0);
  });

  it("open-redirect flags an off-site redirect param", async () => {
    const engine = new HoneypotEngine({ detectors: [openRedirectDetector()] });
    expect((await engine.evaluate(facts({ path: "/login", query: { next: "//evil.example/phish" } }))).detections[0]?.detectorId).toBe("open-redirect");
    expect((await engine.evaluate(facts({ path: "/go", query: { url: "https://evil.example" }, ip: "203.0.113.12" }))).detections[0]?.detectorId).toBe("open-redirect");
    expect((await engine.evaluate(facts({ path: "/login", query: { next: "/dashboard" }, ip: "203.0.113.13" }))).detections).toHaveLength(0);
  });

  it("open-redirect treats same-host and trustedHosts targets as legitimate", async () => {
    // Fallback to request Host: a self-redirect to the same domain is not flagged.
    const byHost = new HoneypotEngine({ detectors: [openRedirectDetector()] });
    expect((await byHost.evaluate(facts({ path: "/cb", query: { redirect_uri: "https://app.example/home" }, headers: { host: "app.example" } }))).detections).toHaveLength(0);
    // But an off-site target with a spoofed Host still can't launder itself past a pinned allowlist:
    const pinned = new HoneypotEngine({ detectors: [openRedirectDetector({ trustedHosts: ["app.example"] })] });
    expect((await pinned.evaluate(facts({ path: "/cb", query: { redirect_uri: "https://app.example/home" }, headers: { host: "evil.example" }, ip: "203.0.113.30" }))).detections).toHaveLength(0);
    expect((await pinned.evaluate(facts({ path: "/cb", query: { redirect_uri: "https://evil.example/x" }, headers: { host: "app.example" }, ip: "203.0.113.31" }))).detections[0]?.detectorId).toBe("open-redirect");
  });

  it("crlf-injection flags encoded CRLF in a query value", async () => {
    const engine = new HoneypotEngine({ detectors: [crlfInjectionDetector()] });
    const r = await engine.evaluate(facts({ path: "/x", query: { q: "foo%0d%0aSet-Cookie:%20admin=1" } }));
    expect(r.detections[0]?.detectorId).toBe("crlf-injection");
  });

  it("web-shell flags a shell filename and an upload-dir script", async () => {
    const engine = new HoneypotEngine({ detectors: [webShellDetector()] });
    expect((await engine.evaluate(facts({ path: "/wso.php" }))).detections[0]?.detectorId).toBe("web-shell");
    expect((await engine.evaluate(facts({ path: "/uploads/avatar.php", ip: "203.0.113.14" }))).detections[0]?.detectorId).toBe("web-shell");
    expect((await engine.evaluate(facts({ path: "/uploads/avatar.png", ip: "203.0.113.15" }))).detections).toHaveLength(0);
  });

  it("nosql-injection flags Mongo operators in query keys and JSON bodies, not bare $ text", async () => {
    const engine = new HoneypotEngine({ detectors: [nosqlInjectionDetector()] });
    expect((await engine.evaluate(facts({ path: "/login", query: { "user[$ne]": "" } }))).detections[0]?.detectorId).toBe("nosql-injection");
    expect((await engine.evaluate(facts({ method: "POST", path: "/login", body: '{"username":"admin","password":{"$ne":null}}', ip: "203.0.113.16" }))).detections[0]?.detectorId).toBe("nosql-injection");
    expect((await engine.evaluate(facts({ path: "/search", query: { q: '{"$where":"sleep(5000)"}' }, ip: "203.0.113.17" }))).detections[0]?.detectorId).toBe("nosql-injection");
    // Legit: array-style params and a price like "$5" must NOT fire.
    expect((await engine.evaluate(facts({ path: "/products", query: { "filter[name]": "widget", sort: "price", note: "costs $5" }, ip: "203.0.113.18" }))).detections).toHaveLength(0);
  });

  it("graphql-abuse flags introspection and deep nesting, not a shallow query", async () => {
    const engine = new HoneypotEngine({ detectors: [graphqlAbuseDetector({ maxDepth: 6 })] });
    expect((await engine.evaluate(facts({ method: "POST", path: "/graphql", body: JSON.stringify({ query: "query IntrospectionQuery { __schema { types { name } } }" }) }))).detections[0]?.detectorId).toBe("graphql-abuse");
    const deep = "query{" + "a{".repeat(8) + "id" + "}".repeat(8) + "}";
    expect((await engine.evaluate(facts({ method: "POST", path: "/graphql", body: JSON.stringify({ query: deep }), ip: "203.0.113.20" }))).detections[0]?.detectorId).toBe("graphql-abuse");
    expect((await engine.evaluate(facts({ method: "POST", path: "/graphql", body: JSON.stringify({ query: "query { me { id name } }" }), ip: "203.0.113.21" }))).detections).toHaveLength(0);
  });

  it("jwt-weakness flags an alg:none token but not a signed one", async () => {
    const engine = new HoneypotEngine({ detectors: [jwtWeaknessDetector()] });
    const noneJwt = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url") + "." + Buffer.from(JSON.stringify({ sub: "admin" })).toString("base64url") + ".";
    expect((await engine.evaluate(facts({ path: "/api/me", headers: { authorization: `Bearer ${noneJwt}` } }))).detections[0]?.detectorId).toBe("jwt-weakness");
    // A normal signed HS256 token must not fire.
    expect((await engine.evaluate(facts({ path: "/api/me", headers: { authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.c2ln" }, ip: "203.0.113.22" }))).detections).toHaveLength(0);
  });

  it("client-anomaly flags a browser UA missing all browser headers, not a real browser or a non-browser UA", async () => {
    const engine = new HoneypotEngine({ detectors: [clientAnomalyDetector()] });
    const chrome = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36";
    expect((await engine.evaluate(facts({ path: "/", headers: { host: "x", "user-agent": chrome } }))).detections[0]?.detectorId).toBe("client-anomaly");
    expect((await engine.evaluate(facts({ path: "/", headers: { host: "x", "user-agent": chrome, accept: "text/html", "accept-language": "en", "accept-encoding": "gzip" }, ip: "203.0.113.23" }))).detections).toHaveLength(0);
    expect((await engine.evaluate(facts({ path: "/", headers: { host: "x", "user-agent": "curl/8.5.0" }, ip: "203.0.113.24" }))).detections).toHaveLength(0);
  });

  it("prototype-pollution flags __proto__ / constructor.prototype, not the words in prose", async () => {
    const engine = new HoneypotEngine({ detectors: [prototypePollutionDetector()] });
    expect((await engine.evaluate(facts({ path: "/api/merge", query: { "a[__proto__][isAdmin]": "true" } }))).detections[0]?.detectorId).toBe("prototype-pollution");
    expect((await engine.evaluate(facts({ method: "POST", path: "/api/merge", body: '{"__proto__":{"isAdmin":true}}', ip: "203.0.113.25" }))).detections[0]?.detectorId).toBe("prototype-pollution");
    expect((await engine.evaluate(facts({ method: "POST", path: "/api/merge", body: '{"a":{"constructor":{"prototype":{"x":1}}}}', ip: "203.0.113.26" }))).detections[0]?.detectorId).toBe("prototype-pollution");
    // Legit: a search discussing constructors and prototypes (words, not key access).
    expect((await engine.evaluate(facts({ path: "/search", query: { q: "how does the constructor and prototype chain work" }, ip: "203.0.113.27" }))).detections).toHaveLength(0);
  });

  it("insecure-deserialization flags Java/PHP payloads, not ordinary base64/text", async () => {
    const engine = new HoneypotEngine({ detectors: [insecureDeserializationDetector()] });
    expect((await engine.evaluate(facts({ path: "/api", headers: { host: "x", cookie: "sess=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA" } }))).detections[0]?.detectorId).toBe("insecure-deserialization");
    expect((await engine.evaluate(facts({ method: "POST", path: "/api", body: 'data=O:4:"Evil":1:{s:3:"cmd";s:2:"id";}', ip: "203.0.113.28" }))).detections[0]?.detectorId).toBe("insecure-deserialization");
    // node-serialize still caught — via the marker that makes the payload execute,
    // which is the only thing that makes it a node-serialize payload at all.
    const nodeSerialize = JSON.stringify({ rce: "_$$ND_FUNC$$_function (){require('child_process').exec('id')}()" });
    expect((await engine.evaluate(facts({ method: "POST", path: "/api", body: nodeSerialize, ip: "203.0.113.29" }))).detections[0]?.detectorId).toBe("insecure-deserialization");
    expect((await engine.evaluate(facts({ path: "/api", headers: { host: "x", cookie: "sess=eyJ1c2VyIjoiYWxpY2UifQ; theme=dark" }, ip: "203.0.113.29" }))).detections).toHaveLength(0);
  });

  it("host-header-injection flags malformed/duplicate hosts, and off-list hosts when expectedHosts is set", async () => {
    const engine = new HoneypotEngine({ detectors: [hostHeaderInjectionDetector()] });
    expect((await engine.evaluate(facts({ path: "/", headers: { host: "evil.com/reset" } }))).detections[0]?.detectorId).toBe("host-header-injection");
    expect((await engine.evaluate(facts({ path: "/", headers: { host: ["a.com", "b.com"] }, ip: "203.0.113.31" }))).detections[0]?.detectorId).toBe("host-header-injection");
    expect((await engine.evaluate(facts({ path: "/", headers: { host: "example.com:8443" }, ip: "203.0.113.32" }))).detections).toHaveLength(0);
    // With a canonical set, an off-list Host (or X-Forwarded-Host) is spoofing.
    const pinned = new HoneypotEngine({ detectors: [hostHeaderInjectionDetector({ expectedHosts: ["example.com"] })] });
    expect((await pinned.evaluate(facts({ path: "/", headers: { host: "attacker.example" }, ip: "203.0.113.33" }))).detections[0]?.detectorId).toBe("host-header-injection");
    expect((await pinned.evaluate(facts({ path: "/", headers: { host: "example.com", "x-forwarded-host": "evil.com" }, ip: "203.0.113.34" }))).detections[0]?.detectorId).toBe("host-header-injection");
    expect((await pinned.evaluate(facts({ path: "/", headers: { host: "example.com" }, ip: "203.0.113.35" }))).detections).toHaveLength(0);
    // An expectedHosts entry written WITH a port must still match a real (port-stripped) Host,
    // and not turn legitimate traffic into a firehose of false positives.
    const withPort = new HoneypotEngine({ detectors: [hostHeaderInjectionDetector({ expectedHosts: ["example.com:8443"] })] });
    expect((await withPort.evaluate(facts({ path: "/", headers: { host: "example.com:8443" }, ip: "203.0.113.36" }))).detections).toHaveLength(0);
    expect((await withPort.evaluate(facts({ path: "/", headers: { host: "example.com" }, ip: "203.0.113.37" }))).detections).toHaveLength(0);
  });
});

describe("new responses (over HTTP)", () => {
  let server: HoneypotServer | undefined;
  afterEach(async () => { await server?.close(); server = undefined; });

  async function serve(respondWith: string): Promise<number> {
    // A trivial detector that routes to the response under test (low score, so the policy honors respondWith).
    const detector = { id: "test", inspect: () => ({ detectorId: "test", reason: "x", score: 1, respondWith }) };
    server = new HoneypotServer({ detectors: [detector] });
    await server.listen(0);
    return (server.address() as { port: number }).port;
  }

  it("fake-success returns 200 + a session cookie", async () => {
    const res = await raw(await serve("fake-success"), "/wp-login.php");
    expect(res.status).toBe(200);
    expect(String(res.headers["set-cookie"])).toContain("session=");
    expect(JSON.parse(res.body.toString()).authenticated).toBe(true);
  });

  it("gzip-bomb returns a small payload that inflates hugely", async () => {
    const res = await raw(await serve("gzip-bomb"), "/x");
    expect(res.headers["content-encoding"]).toBe("gzip");
    expect(res.body.length).toBeLessThan(200_000);       // small on the wire
    expect(gunzipSync(res.body).length).toBe(10 * 1024 * 1024); // 10 MB inflated
  });

  it("rate-limit returns 429 with Retry-After", async () => {
    const res = await raw(await serve("rate-limit"), "/x");
    expect(res.status).toBe(429);
    expect(res.headers["retry-after"]).toBeDefined();
  });

  it("chaos returns either a 5xx or garbage bytes", async () => {
    const res = await raw(await serve("chaos"), "/x");
    const ok = res.status >= 500 || (res.status === 200 && res.headers["content-type"] === "application/octet-stream");
    expect(ok).toBe(true);
  });

  it("fake-data tailors synthesized secrets to the request and never repeats", async () => {
    const port = await serve("fake-data");
    const env = await raw(port, "/.env");
    expect(env.status).toBe(200);
    expect(env.body.toString()).toContain("DATABASE_URL=postgres://");
    expect(env.body.toString()).toContain("AWS_SECRET_ACCESS_KEY=");

    const users = await raw(port, "/api/users");
    expect(users.headers["content-type"]).toContain("application/json");
    const parsed = JSON.parse(users.body.toString());
    expect(Array.isArray(parsed.users)).toBe(true);
    expect(parsed.users[0].password_hash).toMatch(/^\$2b\$12\$/); // bcrypt-shaped, but noise

    // Two hits to the same decoy produce different values — undiffable, unfingerprintable.
    const a = (await raw(port, "/.env")).body.toString();
    const b = (await raw(port, "/.env")).body.toString();
    expect(a).not.toBe(b);
  });
});

describe("SMTP honeypot", () => {
  let smtp: SmtpHoneypot | undefined;
  afterEach(async () => { await smtp?.close(); smtp = undefined; });

  function session(port: number, lines: string[]): Promise<{ transcript: string }> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ port }, () => {});
      let transcript = "";
      let i = 0;
      socket.setTimeout(3000, () => socket.destroy());
      socket.on("data", (d) => {
        transcript += d.toString();
        if (i < lines.length) socket.write(lines[i++] + "\r\n");
        else socket.end();
      });
      socket.on("close", () => resolve({ transcript }));
      socket.on("error", reject);
    });
  }

  it("captures an AUTH LOGIN brute-force attempt as a hit", async () => {
    const hits: HoneypotHit[] = [];
    smtp = new SmtpHoneypot({ port: 0, store: new MemoryStore(), onHit: (h) => { hits.push(h); } });
    await smtp.listen();
    const port = (smtp.address() as { port: number }).port;

    // greeting → EHLO → AUTH LOGIN → base64 user → base64 pass → QUIT
    await session(port, ["EHLO attacker", "AUTH LOGIN", Buffer.from("admin").toString("base64"), Buffer.from("hunter2").toString("base64"), "QUIT"]);
    await new Promise((r) => setTimeout(r, 50));

    const auth = hits.find((h) => h.detections[0]?.detectorId === "smtp-auth-bruteforce");
    expect(auth).toBeTruthy();
    expect(auth?.method).toBe("SMTP");
    expect(auth?.headers["smtp-auth-user"]).toBe("admin");
  });

  it("flags an open-relay attempt to an external domain", async () => {
    const hits: HoneypotHit[] = [];
    smtp = new SmtpHoneypot({ port: 0, localDomains: ["mycorp.test"], onHit: (h) => { hits.push(h); } });
    await smtp.listen();
    const port = (smtp.address() as { port: number }).port;

    await session(port, ["HELO attacker", "MAIL FROM:<spammer@evil.example>", "RCPT TO:<victim@somewhere-else.example>", "QUIT"]);
    await new Promise((r) => setTimeout(r, 50));

    expect(hits.some((h) => h.detections[0]?.detectorId === "smtp-open-relay")).toBe(true);
  });

  // The message-body phase gets no per-line reply, so drive it with one write.
  function sendAll(port: number, lines: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ port }, () => socket.write(lines.join("\r\n") + "\r\n"));
      socket.setTimeout(2000, () => socket.destroy());
      socket.on("data", () => {});
      socket.on("error", reject);
      setTimeout(() => { socket.end(); resolve(); }, 250);
    });
  }

  it("captures the DATA subject and byte count while honoring captureBody=false", async () => {
    const hits: HoneypotHit[] = [];
    smtp = new SmtpHoneypot({ port: 0, captureBody: false, onHit: (h) => { hits.push(h); } });
    await smtp.listen();
    const port = (smtp.address() as { port: number }).port;

    await sendAll(port, ["HELO x", "MAIL FROM:<s@evil.example>", "RCPT TO:<v@evil.example>", "DATA", "Subject: Cheap meds now", "", "Buy http://spam.example", ".", "QUIT"]);
    await new Promise((r) => setTimeout(r, 50));

    const spam = hits.find((h) => h.detections[0]?.detectorId === "smtp-spam");
    expect(spam).toBeTruthy();
    expect(spam?.headers["smtp-subject"]).toBe("Cheap meds now");
    expect(Number(spam?.headers["smtp-message-bytes"])).toBeGreaterThan(0);
    expect(spam?.body).toBeUndefined(); // captureBody:false → raw body not stored
  });

  it("stores the raw body when captureBody is on (default)", async () => {
    const hits: HoneypotHit[] = [];
    smtp = new SmtpHoneypot({ port: 0, onHit: (h) => { hits.push(h); } });
    await smtp.listen();
    const port = (smtp.address() as { port: number }).port;

    await sendAll(port, ["HELO x", "MAIL FROM:<s@evil.example>", "RCPT TO:<v@evil.example>", "DATA", "Subject: hi", "", "malware-payload-marker", ".", "QUIT"]);
    await new Promise((r) => setTimeout(r, 50));

    const spam = hits.find((h) => h.detections[0]?.detectorId === "smtp-spam");
    expect(spam?.body).toContain("malware-payload-marker");
  });
});

describe("SSH honeypot", () => {
  let ssh: SshHoneypot | undefined;
  afterEach(async () => { await ssh?.close(); ssh = undefined; });

  it("captures a password brute-force attempt (username + password) as a hit", async () => {
    const hits: HoneypotHit[] = [];
    ssh = new SshHoneypot({ port: 0, store: new MemoryStore(), onHit: (h) => { hits.push(h); } });
    await ssh.listen();
    const port = (ssh.address() as { port: number }).port;

    // ssh2 client attempts password auth; the honeypot rejects it, so the client errors out.
    await new Promise<void>((resolve) => {
      const conn = new Client();
      conn.on("ready", () => { conn.end(); resolve(); }); // should never happen
      conn.on("error", () => resolve());                  // expected: auth rejected
      conn.connect({ host: "127.0.0.1", port, username: "root", password: "hunter2", hostVerifier: () => true, readyTimeout: 4000 });
    });
    await new Promise((r) => setTimeout(r, 80));

    const auth = hits.find((h) => h.detections[0]?.detectorId === "ssh-auth-bruteforce");
    expect(auth).toBeTruthy();
    expect(auth?.method).toBe("SSH");
    expect(auth?.headers["ssh-user"]).toBe("root");
    expect(auth?.body).toBe("hunter2"); // the captured password
  }, 15000);

  it("in interactive mode, accepts the login and captures shell commands", async () => {
    const hits: HoneypotHit[] = [];
    ssh = new SshHoneypot({ port: 0, interactive: true, acceptOnAttempt: 1, store: new MemoryStore(), onHit: (h) => { hits.push(h); } });
    await ssh.listen();
    const port = (ssh.address() as { port: number }).port;

    await new Promise<void>((resolve, reject) => {
      const conn = new Client();
      // Self-pace off the shell prompt so writes never race the channel setup.
      const cmds = ["whoami", "cat /etc/passwd", "exit"];
      let idx = 0;
      conn.on("ready", () => {
        conn.shell((err, stream) => {
          if (err) return reject(err);
          stream.on("close", () => { conn.end(); resolve(); });
          let buf = "";
          stream.on("data", (d: Buffer) => {
            buf += d.toString();
            if (buf.endsWith("# ") && idx < cmds.length) {
              buf = "";
              stream.write(cmds[idx++] + "\n");
            }
          });
        });
      });
      conn.on("error", reject);
      conn.connect({ host: "127.0.0.1", port, username: "root", password: "letmein", hostVerifier: () => true, readyTimeout: 4000 });
    });
    await new Promise((r) => setTimeout(r, 100));

    const commands = hits.filter((h) => h.detections[0]?.detectorId === "ssh-shell-command").map((h) => h.body);
    expect(commands).toContain("whoami");
    expect(commands).toContain("cat /etc/passwd");
    const summary = hits.find((h) => h.detections[0]?.detectorId === "ssh-shell-session");
    expect(summary).toBeTruthy();
    expect(Number(summary?.headers["ssh-command-count"])).toBeGreaterThanOrEqual(2);
  }, 15000);

  it("closes a held-open connection after maxSessionMs (slow connection-hold DoS defense)", async () => {
    ssh = new SshHoneypot({ port: 0, interactive: true, acceptOnAttempt: 1, maxSessionMs: 400 });
    await ssh.listen();
    const port = (ssh.address() as { port: number }).port;

    const start = Date.now();
    await new Promise<void>((resolve, reject) => {
      const conn = new Client();
      // Open a shell and then sit idle — without the lifetime cap this would hold forever.
      conn.on("ready", () => conn.shell((err, stream) => { if (err) reject(err); else stream.on("data", () => {}); }));
      conn.on("close", () => resolve());          // the honeypot's timer ends the connection
      conn.on("error", () => resolve());          // either way the socket is gone
      conn.connect({ host: "127.0.0.1", port, username: "root", password: "x", hostVerifier: () => true, readyTimeout: 4000 });
    });
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(3000);   // closed by the ~400ms timer, not held open
  }, 15000);
});
