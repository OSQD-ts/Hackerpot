import type { Server } from "node:http";

/**
 * Applies conservative timeouts and a connection ceiling to an HTTP server so an
 * attacker can't exhaust it by holding connections open. Node's defaults are permissive
 * (no connection cap, a 5-minute request timeout), which on an internet-facing honeypot
 * is a **Slowloris** invitation — trickle headers a byte at a time and pin every socket.
 *
 * The values are hard-coded rather than configurable on purpose: no legitimate request
 * needs 20s to send its headers, and there's no safe way for an operator to relax these
 * into the vulnerable case. Tune only if you have a genuine reason to.
 */
export function hardenHttpServer(server: Server): void {
  // Full request (headers + body) must arrive within this long, or the socket is closed.
  server.requestTimeout = 30_000;
  // Headers specifically must complete well before that — the core Slowloris defense.
  server.headersTimeout = 20_000;
  // Idle keep-alive sockets don't linger.
  server.keepAliveTimeout = 5_000;
  // Catch-all socket inactivity timeout (0 = off in Node; we want a bound).
  server.timeout = 60_000;
  // Ceiling on simultaneous connections — generous enough for real traffic behind a
  // proxy, low enough that a flood can't open unbounded sockets against us.
  server.maxConnections = 10_000;
}
