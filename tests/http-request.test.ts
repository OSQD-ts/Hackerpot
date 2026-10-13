import http from "node:http";
import { describe, expect, it } from "vitest";
import { createMiddleware, type MiddlewareOptions, type NextFn } from "../src/adapters/node.js";
import { HoneypotEngine } from "../src/core.js";
import { MemoryStore } from "../src/stores/index.js";
import { readBody } from "../src/internal/http.js";

/** Drive a middleware over a real socket and report what the host app saw. */
async function throughMiddleware(
  engine: HoneypotEngine,
  init: { path: string; method?: string; body?: string },
  options: MiddlewareOptions = {},
): Promise<{ status: number; nexted: boolean; nextErr: unknown }> {
  const middleware = createMiddleware(engine, options);
  let nexted = false;
  let nextErr: unknown;
  const next: NextFn = (err) => {
    nexted = true;
    nextErr = err;
  };
  const server = http.createServer((req, res) => {
    void middleware(req, res, (err) => {
      next(err);
      if (!res.writableEnded) {
        res.statusCode = err ? 500 : 204;
        res.end();
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as { port: number };
  try {
    const res = await fetch(`http://127.0.0.1:${port}${init.path}`, {
      method: init.method ?? "POST",
      ...(init.body !== undefined ? { body: init.body } : {}),
    });
    await res.arrayBuffer();
    return { status: res.status, nexted, nextErr };
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

describe("request bodies are decoded and bounded correctly", () => {
  /** Feed `chunks` to readBody() through a real HTTP request. */
  async function bodyFrom(chunks: Buffer[]): Promise<string | undefined> {
    let seen: string | undefined;
    const server = http.createServer((req, res) => {
      void readBody(req).then((body) => {
        seen = body;
        res.end();
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as { port: number };
    try {
      await fetch(`http://127.0.0.1:${port}/`, {
        method: "POST",
        body: new ReadableStream({
          start(controller) {
            for (const chunk of chunks) controller.enqueue(new Uint8Array(chunk));
            controller.close();
          },
        }),
        // undici requires this for a streaming request body
        duplex: "half",
      });
      return seen;
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  }

  it("reassembles a multi-byte character split across two chunks", async () => {
    // "€" is E2 82 AC. Decoding each chunk on its own yields replacement characters,
    // silently mutating the bytes every body detector then matches against.
    const euro = Buffer.from("€", "utf8");
    const body = await bodyFrom([Buffer.concat([Buffer.from("a="), euro.subarray(0, 2)]), euro.subarray(2)]);
    expect(body).toBe("a=€");
  });

  it("keeps the prefix of an oversized body rather than dropping the chunk that crossed the cap", async () => {
    // The payload always sits near the front, so truncation must cut at the cap — not
    // discard whole chunks and end the body at an arbitrary boundary.
    const body = await bodyFrom([Buffer.from("q=' UNION SELECT 1"), Buffer.alloc(128 * 1024, 0x41)]);
    expect(body?.startsWith("q=' UNION SELECT 1AAA")).toBe(true);
    expect(body).toContain("[truncated]");
    expect(body!.length).toBeLessThan(70 * 1024);
  });

  it("does not read a body for methods that cannot carry one", async () => {
    const engine = new HoneypotEngine({ store: new MemoryStore() });
    const result = await throughMiddleware(engine, { path: "/api/orders", method: "GET" });
    expect(result.nexted).toBe(true);
  });
});
