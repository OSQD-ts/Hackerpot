import { gzipSync } from "node:zlib";
import type { ResponseAction, ResponseContext } from "./types.js";

export interface GzipBombOptions {
  /** How many bytes the response inflates to on the client. Default 10 MB. */
  decompressedBytes?: number;
  contentType?: string;
}

/**
 * Serves a small gzip-compressed response that inflates to something large on
 * the attacker's side — a decompression bomb. A few KB on the wire becomes tens
 * of megabytes in a naive scraper's memory. Purely defensive here: it only ever
 * answers a request already flagged as hostile.
 *
 * The compressed payload is built once per configuration and cached, so serving
 * it costs almost nothing.
 */
export function gzipBombAction(options: GzipBombOptions = {}): ResponseAction {
  const decompressedBytes = options.decompressedBytes ?? 10 * 1024 * 1024;
  const contentType = options.contentType ?? "text/html; charset=utf-8";
  let cached: Buffer | undefined;

  const compressed = (): Buffer => {
    if (!cached) cached = gzipSync(Buffer.alloc(decompressedBytes, 0x20), { level: 9 }); // spaces compress ~1000:1
    return cached;
  };

  return {
    id: "gzip-bomb",
    description: "Serve a small gzip payload that inflates hugely on the attacker's side",
    execute(ctx: ResponseContext): void {
      const body = compressed();
      ctx.res.statusCode = 200;
      ctx.res.setHeader("Content-Type", contentType);
      ctx.res.setHeader("Content-Encoding", "gzip");
      ctx.res.setHeader("Content-Length", String(body.length));
      ctx.res.end(body);
    },
  };
}
