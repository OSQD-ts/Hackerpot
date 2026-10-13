import http from "node:http";
import net from "node:net";
import { describe, expect, it } from "vitest";
import { isSecretHeader, maskIp, redactIncident, REDACTED } from "../src/management/redact.js";
import type { HoneypotHit } from "../src/types.js";
import { IncidentBroker } from "../src/management/broker.js";
import { WebhookDispatcher } from "../src/management/webhooks.js";

/**
 * What leaves the process, and what a deployment is allowed to decide about it. The two
 * questions are separate on purpose: a receiver may be trusted with credentials and still
 * have no business knowing which household an address belongs to.
 */

const incident = (over: Partial<HoneypotHit> = {}): HoneypotHit => ({
  id: "a",
  timestamp: "2026-09-16T12:00:00.000Z",
  ip: "198.51.100.77",
  method: "POST",
  path: "/wp-login.php",
  headers: { authorization: "Bearer super-secret-value", "x-acme-automation-token": "another-secret-value", "x-acme-bypass": "third-secret-value", "user-agent": "curl/8.4.0" },
  body: "user=ada&password=hunter2000",
  detections: [{ detector: "credential-bruteforce", summary: "tried Bearer super-secret-value", score: 9 }],
  score: 9,
  totalScore: 9,
  respondedWith: "rate-limit",
  ...over,
});

const hit = (overrides: Partial<HoneypotHit> = {}): HoneypotHit => ({
  id: "hit-1",
  timestamp: new Date().toISOString(),
  ip: "203.0.113.20",
  method: "POST",
  path: "/login",
  headers: { "user-agent": "curl/8.4.0" },
  detections: [{ detector: "decoy-path", summary: "probe", score: 5 }],
  score: 5,
  totalScore: 5,
  respondedWith: "not-found",
  ...overrides,
});

async function until(check: () => boolean, ms = 5_000): Promise<void> {
  const started = Date.now();
  while (!check()) {
    if (Date.now() - started > ms) throw new Error("condition not met in time");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

describe("addresses", () => {
  it("coarsens to a network, and says the same thing everywhere", () => {
    expect(maskIp("198.51.100.77")).toBe("198.51.100.0/24");
    expect(maskIp("::ffff:198.51.100.77")).toBe("198.51.100.0/24");
    expect(maskIp("2001:db8:1234:5678::1")).toBe("2001:db8:1234::/48");
    // Not an address at all: left alone rather than mangled into something that looks like one.
    expect(maskIp("not-an-address")).toBe("not-an-address");
  });

  it("is off unless asked, because a receiver may be acting on the address", () => {
    expect(redactIncident(incident()).ip).toBe("198.51.100.77");
    expect(redactIncident(incident(), { maskIp: true }).ip).toBe("198.51.100.0/24");
  });
});

describe("credentials", () => {
  it("keeps a JSON body's __proto__ key, which is the payload of a prototype-pollution probe", () => {
    // Redacted and rebuilt: the secret goes, the attack stays.
    const withSecret = redactIncident(incident({ body: '{"__proto__":{"isAdmin":true},"password":"hunter2000"}', headers: { "content-type": "application/json" } }));
    expect(withSecret.body).toContain('"__proto__":{"isAdmin":true}');
    expect(withSecret.body).not.toContain("hunter2000");
    // Nothing to redact: the body as sent, byte for byte, spacing included.
    const raw = '{ "__proto__": { "isAdmin": true } }';
    expect(redactIncident(incident({ body: raw, headers: { "content-type": "application/json" } })).body).toBe(raw);
  });

  it("hides a header whose name says what it holds, and scrubs the quote of it", () => {
    const out = redactIncident(incident());
    expect(out.headers["authorization"]).toBe("[redacted]");
    // A header this library has never heard of, whose name says what it holds.
    expect(out.headers["x-acme-automation-token"]).toBe("[redacted]");
    // And one whose name says nothing: the guess cannot catch it, so it is shown until a
    // deployment names it. That is what `secretHeaders` is for.
    expect(out.headers["x-acme-bypass"]).toBe("third-secret-value");
    expect(out.headers["user-agent"]).toBe("curl/8.4.0");
    // Detectors quote what they saw, so the value must not survive a few fields away.
    expect(out.detections[0]?.summary).not.toContain("super-secret-value");
    expect(out.body).not.toContain("hunter2000");
    expect(out.body).toContain("password");
  });

  it("can be told exactly which headers are secret, and to stop guessing", () => {
    const strict = redactIncident(incident(), { guessSecretHeaders: false });
    // The guess is off, so a name nobody listed is shown…
    expect(strict.headers["x-acme-automation-token"]).toBe("another-secret-value");
    // …while the headers that carry a credential by definition are still hidden.
    expect(strict.headers["authorization"]).toBe("[redacted]");

    const named = redactIncident(incident(), { guessSecretHeaders: false, secretHeaders: ["x-acme-bypass"] });
    expect(named.headers["x-acme-bypass"]).toBe("[redacted]");
  });

  it("can be switched off independently of masking", () => {
    const raw = redactIncident(incident(), { credentials: false, maskIp: true });
    expect(raw.headers["authorization"]).toBe("Bearer super-secret-value");
    expect(raw.body).toContain("hunter2000");
    expect(raw.ip).toBe("198.51.100.0/24");
  });

  it("knows a credential header by definition and by shape", () => {
    expect(isSecretHeader("cookie")).toBe(true);
    expect(isSecretHeader("x-acme-api-key")).toBe(true);
    expect(isSecretHeader("x-acme-api-key", new Set(), false)).toBe(false);
    expect(isSecretHeader("x-team", new Set(["x-team"]))).toBe(true);
    expect(isSecretHeader("user-agent")).toBe(false);
  });
});

describe("webhook redaction", () => {
  const secretHit = (): HoneypotHit =>
    hit({
      headers: {
        authorization: "Bearer supersecretvalue123",
        cookie: "sid=abcdefgh12345",
        "x-acme-api-key": "key-9999999999",
        "user-agent": "curl/8.4.0",
      },
      body: "user=admin&password=hunter2hunter2",
      detections: [{ detector: "payload-injection", summary: "sql-injection payload detected in body", score: 10, metadata: { sample: "user=admin&password=hunter2hunter2" } }],
    });

  it("strips credential headers, secret-named headers and form passwords, including quoted copies", () => {
    const out = redactIncident(secretHit());
    expect(out.headers).toMatchObject({ authorization: REDACTED, cookie: REDACTED, "x-acme-api-key": REDACTED, "user-agent": "curl/8.4.0" });
    expect(out.body).toBe(`user=admin&password=${REDACTED}`);
    expect(JSON.stringify(out.detections)).not.toContain("hunter2hunter2");
  });

  it("strips secret-named JSON body fields at any depth", () => {
    const out = redactIncident(hit({ body: JSON.stringify({ login: { username: "root", password: "toor-toor" }, api_key: "abcd-efgh" }) }));
    expect(out.body).not.toContain("toor-toor");
    expect(out.body).not.toContain("abcd-efgh");
    expect(out.body).toContain("root");
  });

  it("never modifies the incident it was given", () => {
    const original = secretHit();
    redactIncident(original);
    expect(original.headers["authorization"]).toBe("Bearer supersecretvalue123");
  });

  it("is applied to delivered webhooks by default, and skipped with redact: false", async () => {
    const received: Array<{ incident: HoneypotHit }> = [];
    const receiver = http.createServer((req, res) => {
      let data = "";
      req.on("data", (chunk) => (data += chunk));
      req.on("end", () => {
        received.push(JSON.parse(data));
        res.end("ok");
      });
    });
    await new Promise<void>((resolve) => receiver.listen(0, "127.0.0.1", resolve));
    const { port } = receiver.address() as net.AddressInfo;
    try {
      const broker = new IncidentBroker();
      new WebhookDispatcher({ webhooks: [{ url: `http://127.0.0.1:${port}/redacted` }] }).attach(broker);
      new WebhookDispatcher({ webhooks: [{ url: `http://127.0.0.1:${port}/verbatim`, redact: false }] }).attach(broker);
      broker.publish(secretHit());
      await until(() => received.length === 2);
      const values = received.map((payload) => payload.incident.headers["authorization"]).sort();
      expect(values).toEqual(["Bearer supersecretvalue123", REDACTED].sort());
    } finally {
      await new Promise<void>((resolve) => receiver.close(() => resolve()));
    }
  });
});
