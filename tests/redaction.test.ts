import { describe, expect, it } from "vitest";
import { isSecretHeader, maskIp, redactIncident } from "../src/management/redact.js";
import type { HoneypotHit } from "../src/types.js";

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
  detections: [{ detectorId: "credential-bruteforce", reason: "tried Bearer super-secret-value", score: 9 }],
  score: 9,
  totalScore: 9,
  respondedWith: "rate-limit",
  ...over,
});

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
    expect(out.detections[0]?.reason).not.toContain("super-secret-value");
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
