import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { HoneypotEngine } from "../core.js";
import { createMiddleware, type HoneypotMiddleware, type MiddlewareOptions } from "../middleware.js";

export interface FetchHoneypotContext {
  /**
   * The client's address. A Fetch `Request` does not carry one, so the host passes it in:
   * the socket's remote address, or whatever the framework exposes. Without it every
   * request shares one address, and `trustProxy` falls back to `X-Forwarded-For`.
   */
  ip?: string;
}

export type FetchHandler = (request: Request) => Response | Promise<Response>;

/** Resolves to the honeypot's `Response`, or `undefined` when the request should go to your handler. */
export type FetchHoneypot = (request: Request, context?: FetchHoneypotContext) => Promise<Response | undefined>;

const encoder = new TextEncoder();

/** Statuses a `Response` must not carry a body with. */
const NULL_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);

/** Bytes buffered for a slow reader before `write()` reports backpressure, as a socket would. */
const HIGH_WATER_MARK = 64 * 1024;

/**
 * The parts of `IncomingMessage` the middleware reads, backed by a Fetch `Request`.
 *
 * The body is only read once something listens for `data`, which the middleware does only
 * for a request the honeypot is answering. Reading it eagerly would lock the stream, and a
 * request passed on to the app would reach its handler with a body it could not read.
 */
class FetchRequestShim extends EventEmitter {
  readonly method: string;
  readonly url: string;
  readonly headers: Record<string, string> = {};
  readonly rawHeaders: string[] = [];
  readonly httpVersion = "1.1";
  readonly socket: { remoteAddress: string | undefined };
  private started = false;

  constructor(private readonly request: Request, ip: string | undefined) {
    super();
    const url = new URL(request.url);
    this.method = request.method;
    this.url = `${url.pathname}${url.search}`;
    this.socket = { remoteAddress: ip };
    // Header order: a Fetch runtime normalises it, so the actor fingerprint has less to go on here.
    request.headers.forEach((value, name) => {
      this.headers[name] = value;
      this.rawHeaders.push(name, value);
    });
    // Many runtimes drop `Host` from a Request, and the authority is right there in the URL.
    // Leaving it absent would have `header-anomaly` flag every request as "missing Host":
    // an argument from absence about something the runtime removed, not the client.
    this.headers["host"] ??= url.host;
  }

  override on(event: string | symbol, listener: (...args: unknown[]) => void): this {
    super.on(event, listener);
    if (event === "data" && !this.started) {
      this.started = true;
      void this.pump();
    }
    return this;
  }

  private async pump(): Promise<void> {
    const body = this.request.body;
    if (body === null) {
      queueMicrotask(() => this.emit("end"));
      return;
    }
    const reader = body.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        this.emit("data", Buffer.from(value));
      }
      this.emit("end");
    } catch (error) {
      this.emit("error", error);
    }
  }
}

/**
 * The parts of `ServerResponse` the response actions use, backed by a streaming `Response`.
 *
 * The `Response` is created as soon as headers are committed (the first write, or the
 * end), and its body keeps streaming after that, so a drip-feed or large payload reaches
 * the client as it is written. `write()` reports backpressure once the stream holds more
 * than a socket would buffer, and `drain` fires when the reader catches up. The client
 * going away (the request's abort signal, or the reader cancelling) is a `close`, exactly
 * what tarpit, drip-feed and large-payload already listen for.
 */
class FetchResponseShim extends EventEmitter {
  statusCode = 200;
  headersSent = false;
  writableEnded = false;
  destroyed = false;
  readonly response: Promise<Response>;
  private resolveResponse!: (response: Response) => void;
  private readonly responseHeaders = new Headers();
  private controller!: ReadableStreamDefaultController<Uint8Array>;
  private readonly stream: ReadableStream<Uint8Array>;

  constructor(signal: AbortSignal | undefined) {
    super();
    this.response = new Promise((resolve) => (this.resolveResponse = resolve));
    this.stream = new ReadableStream<Uint8Array>(
      {
        start: (controller) => {
          this.controller = controller;
        },
        pull: () => {
          this.emit("drain");
        },
        cancel: () => this.close(),
      },
      { highWaterMark: HIGH_WATER_MARK, size: (chunk) => chunk.byteLength },
    );
    if (signal !== undefined) {
      if (signal.aborted) this.close();
      else signal.addEventListener("abort", () => this.close(), { once: true });
    }
  }

  setHeader(name: string, value: number | string | readonly string[]): this {
    if (this.headersSent) throw new Error(`Cannot set header "${name}" after the response has started`);
    if (Array.isArray(value)) {
      this.responseHeaders.delete(name);
      for (const one of value) this.responseHeaders.append(name, one);
    } else {
      this.responseHeaders.set(name, String(value));
    }
    return this;
  }

  getHeader(name: string): string | undefined {
    return this.responseHeaders.get(name) ?? undefined;
  }

  write(chunk: string | Uint8Array): boolean {
    if (this.destroyed || this.writableEnded) return false;
    this.commit();
    const bytes = typeof chunk === "string" ? encoder.encode(chunk) : chunk;
    if (bytes.byteLength > 0) this.controller.enqueue(bytes);
    return (this.controller.desiredSize ?? 1) > 0;
  }

  end(chunk?: string | Uint8Array): this {
    if (this.writableEnded) return this;
    if (chunk !== undefined) this.write(chunk);
    this.commit();
    this.writableEnded = true;
    if (!this.destroyed) {
      try {
        this.controller.close();
      } catch {
        // Already closed or cancelled by the reader; nothing left to flush.
      }
    }
    this.emit("finish");
    return this;
  }

  /** Nothing to resume on a Fetch response; present so code written for Node's objects runs unchanged. */
  resume(): this {
    return this;
  }

  /** The client went away. */
  close(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    this.emit("close");
  }

  private commit(): void {
    if (this.headersSent) return;
    this.headersSent = true;
    try {
      const body = NULL_BODY_STATUSES.has(this.statusCode) ? null : this.stream;
      this.resolveResponse(new Response(body, { status: this.statusCode, headers: this.responseHeaders }));
    } catch {
      // A status a `Response` cannot represent (outside 200–599) must not leave the caller waiting forever.
      this.resolveResponse(new Response(null, { status: 500 }));
    }
  }
}

interface FetchOutcome {
  /** The honeypot's answer, when it answered. */
  response?: Response;
  /** Reports the status your handler answered a passed request with, for the 404 gating. */
  passedWith(status: number): void;
}

async function evaluate(middleware: HoneypotMiddleware, request: Request, context: FetchHoneypotContext): Promise<FetchOutcome> {
  const req = new FetchRequestShim(request, context.ip);
  const res = new FetchResponseShim(request.signal);
  let passed = false;
  let passedError: unknown;
  const handled = middleware(req as unknown as IncomingMessage, res as unknown as ServerResponse, (err) => {
    passed = true;
    passedError = err;
  });

  // The middleware either passes the request on or answers it on `res`, and an answer can
  // start long before the action finishes (a drip-feed keeps writing), so whichever comes
  // first decides.
  await Promise.race([handled, res.response]);
  if (passed) {
    // Only reachable with `failOpen: false`.
    if (passedError !== undefined) throw passedError;
    return {
      passedWith: (status) => {
        res.statusCode = status;
        res.emit("finish");
      },
    };
  }
  return { response: await res.response, passedWith: () => undefined };
}

/**
 * The honeypot as a Fetch-API step, for handlers shaped `(request: Request) => Response`:
 * Hono, Next.js route handlers, and the like, on a Node-compatible runtime.
 *
 * ```ts
 * const honeypot = fetchHoneypot(engine);
 * const handled = await honeypot(request, { ip });
 * if (handled) return handled;
 * ```
 *
 * Same two-phase evaluation, proof guard and failure handling as `createMiddleware`. A
 * request's body is read only when the honeypot answers it, so one passed on can still be
 * read by your handler. Two limits: pass the client IP (a `Request` has none), and the
 * runtime normalises header order, so the actor fingerprint is weaker than on Node's own
 * server. The engine uses Node built-ins, so edge runtimes without them are not supported.
 *
 * `path-bruteforce` counts a passed path only once it is known to be a 404, which this
 * function never learns. Use `withFetchHoneypot` to wrap your handler and report it.
 */
export function fetchHoneypot(engine: HoneypotEngine, options: MiddlewareOptions = {}): FetchHoneypot {
  const middleware = createMiddleware(engine, options);
  return async (request, context = {}) => (await evaluate(middleware, request, context)).response;
}

/**
 * Wraps a Fetch handler: the honeypot answers what it catches, your handler answers the
 * rest, and your handler's status is reported back so `path-bruteforce` counts misses.
 *
 * ```ts
 * export default { fetch: withFetchHoneypot(engine, app.fetch) };
 * ```
 */
export function withFetchHoneypot(
  engine: HoneypotEngine,
  handler: FetchHandler,
  options: MiddlewareOptions = {},
): (request: Request, context?: FetchHoneypotContext) => Promise<Response> {
  const middleware = createMiddleware(engine, options);
  return async (request, context = {}) => {
    const outcome = await evaluate(middleware, request, context);
    if (outcome.response !== undefined) return outcome.response;
    const response = await handler(request);
    outcome.passedWith(response.status);
    return response;
  };
}
