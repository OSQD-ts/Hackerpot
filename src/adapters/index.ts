/**
 * Every way to put the honeypot in front of an application, from one import path:
 * `@osqd/hackerpot/adapters`.
 *
 * Split out of the main entry the way bothandlerjs splits its adapters: an edge deployment
 * that needs only the Fetch adapter should be able to say so. Everything here is also
 * exported from the package root, so nothing that already imports from there changes.
 */
export { createMiddleware, dispatch, trapFormGuard } from "../middleware.js";
export type { HoneypotMiddleware, MiddlewareOptions, NextFn } from "../middleware.js";
export { koaHoneypot } from "./koa.js";
export type { KoaHoneypotMiddleware, KoaLikeContext } from "./koa.js";
export { fastifyHoneypot } from "./fastify.js";
export type { FastifyHoneypotHook, FastifyLikeReply, FastifyLikeRequest } from "./fastify.js";
export { fetchHoneypot, withFetchHoneypot } from "./fetch.js";
export type { FetchHandler, FetchHoneypot, FetchHoneypotContext } from "./fetch.js";
export { createDashboardHandler } from "../dashboard/index.js";
