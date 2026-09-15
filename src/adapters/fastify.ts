import type { IncomingMessage, ServerResponse } from "node:http";
import type { HoneypotEngine } from "../core.js";
import { createMiddleware, type MiddlewareOptions } from "../middleware.js";

/** The parts of a Fastify request this hook touches, described structurally so there is no dependency on Fastify. */
export interface FastifyLikeRequest {
  raw: IncomingMessage;
}

/** The parts of a Fastify reply this hook touches. */
export interface FastifyLikeReply {
  raw: ServerResponse;
  hijack(): void;
}

export type FastifyHoneypotHook = (request: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<void>;

/**
 * A Fastify `onRequest` hook around `createMiddleware`.
 *
 * ```ts
 * fastify.addHook("onRequest", fastifyHoneypot(engine));
 * ```
 *
 * `onRequest` is the earliest hook, so the body is still unread: the honeypot reads it
 * only for a request it is answering, and Fastify's parser gets an intact stream
 * otherwise. When the honeypot answers, the reply is hijacked so Fastify neither routes
 * the request nor tries to send a second response.
 */
export function fastifyHoneypot(engine: HoneypotEngine, options: MiddlewareOptions = {}): FastifyHoneypotHook {
  const middleware = createMiddleware(engine, options);
  return async function honeypotOnRequest(request, reply) {
    let passed = false;
    let passedError: unknown;
    await middleware(request.raw, reply.raw, (err) => {
      passed = true;
      passedError = err;
    });
    if (!passed) {
      reply.hijack();
      return;
    }
    // Only reachable with `failOpen: false`: a throw from an `onRequest` hook is Fastify's error path.
    if (passedError !== undefined) throw passedError;
  };
}
