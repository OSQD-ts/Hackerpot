import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import { describe, expect, it } from "vitest";
import { MemoryBlocklist } from "../src/blocklist.js";
import { HoneypotEngine } from "../src/core.js";
import { scannerSignatureDetector } from "../src/detectors/index.js";
import type { DetectionContext } from "../src/detectors/types.js";
import { createMiddleware, type MiddlewareOptions } from "../src/middleware.js";
import type { HoneypotHit } from "../src/types.js";

const CHROME = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
const IP = "203.0.113.40";

function fakeReq(path: string, userAgent: string): IncomingMessage {
  const headers = { host: "shop.example", "user-agent": userAgent, accept: "text/html,*/*", "accept-language": "en-US", "accept-encoding": "gzip" };
  return Object.assign(new EventEmitter(), {
    method: "GET",
    url: path,
    headers,
    rawHeaders: Object.entries(headers).flat(),
    httpVersion: "1.1",
    socket: { remoteAddress: IP },
  }) as unknown as IncomingMessage;
}

function fakeRes(): ServerResponse {
  const res = Object.assign(new EventEmitter(), {
    statusCode: 200,
    headersSent: false,
    writableEnded: false,
    destroyed: false,
    setHeader: () => undefined,
    write: () => true,
    end: () => {
      res.writableEnded = true;
      res.emit("finish");
    },
  });
  return res as unknown as ServerResponse;
}

/** A middleware whose policy always asks for a block, so the guard is the only variable. */
async function probe(userAgent: string, options: MiddlewareOptions = { unprovenBlockFallback: "not-found" }) {
  const hits: HoneypotHit[] = [];
  const blocklist = new MemoryBlocklist();
  const engine = new HoneypotEngine({ enricher: null, blocklist, policy: () => "block", onHit: (hit) => void hits.push(hit) });
  await createMiddleware(engine, options)(fakeReq("/.env", userAgent), fakeRes(), () => undefined);
  return { hit: hits[0]!, blocked: blocklist.isBlocked(IP) };
}

describe("middleware only blocks on proof", () => {
  it("downgrades a block that rests on suspicion alone, and blocklists nothing", async () => {
    const { hit, blocked } = await probe(CHROME);
    expect(hit.respondedWith).toBe("not-found");
    expect(hit.downgradedFrom).toBe("block");
    expect(blocked).toBe(false);
  });

  it("blocks when a detection is proof: a self-declared attack tool", async () => {
    const { hit, blocked } = await probe("sqlmap/1.7.2#stable (https://sqlmap.org)");
    expect(hit.respondedWith).toBe("block");
    expect(hit.downgradedFrom).toBeUndefined();
    expect(blocked).toBe(true);
  });

  it("blocks on score alone with blockRequiresProof: false", async () => {
    const { hit, blocked } = await probe(CHROME, { blockRequiresProof: false });
    expect(hit.respondedWith).toBe("block");
    expect(blocked).toBe(true);
  });

  it("refuses a fallback that is itself a block", () => {
    expect(() => createMiddleware(new HoneypotEngine(), { unprovenBlockFallback: "block" })).toThrow(/unprovenBlockFallback/);
  });

  it("leaves standalone evaluation blocking on score", async () => {
    const engine = new HoneypotEngine({ enricher: null, policy: () => "block" });
    const result = await engine.evaluate({ method: "GET", path: "/.env", query: {}, headers: { host: "x", "user-agent": CHROME }, ip: IP });
    expect(result.actionId).toBe("block");
    expect(result.downgradedFrom).toBeUndefined();
  });
});

describe("scanner-signature marks only attack tools as proof", () => {
  const ctx = (userAgent: string): DetectionContext =>
    ({ method: "GET", path: "/", query: {}, headers: { "user-agent": userAgent }, ip: IP, timestamp: new Date(), fingerprint: "", tracker: undefined as never, fingerprintRegistry: undefined as never }) as DetectionContext;
  const detector = scannerSignatureDetector();

  it.each(["sqlmap/1.7", "Mozilla/5.0 (compatible; Nmap Scripting Engine)", "Nuclei - Open-source project"])("%s is proof", async (userAgent) => {
    expect((await detector.inspect(ctx(userAgent)))?.certain).toBe(true);
  });

  it.each(["curl/8.4.0", "python-requests/2.31.0"])("%s is only suspicion", async (userAgent) => {
    const detection = await detector.inspect(ctx(userAgent));
    expect(detection).toBeDefined();
    expect(detection?.certain).toBeUndefined();
  });
});
