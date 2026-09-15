import type { IncomingMessage, ServerResponse } from "node:http";

/**
 * How a viewer proves they may read the dashboard.
 *
 * There is no default on a listener anyone else can reach, and that is deliberate. The page
 * shows attacker addresses, captured request bodies, credentials an attacker tried, and
 * which detector fired on what — which for an attacker probing your deployment is a map of
 * exactly what to avoid next. So a dashboard bound anywhere but loopback, or mounted on a
 * server of yours, refuses to start until something explicit has been said about access.
 * Adapted from bothandlerjs.
 */
export type DashboardAuth =
  /** HTTP Basic. Both halves are compared in constant time. */
  | { username: string; password: string }
  /**
   * A shared secret, accepted as `Authorization: Bearer <token>` or as `?token=<token>` so a
   * link can be opened directly. The query form lands in browser history and proxy logs:
   * fine for a laptop, a poor idea for a shared deployment.
   */
  | { token: string }
  /**
   * Your own check: a session cookie, an SSO header your gateway sets, an mTLS subject.
   * Return `true` or a non-empty string (such as the viewer's name) to admit, and anything
   * else, including `""`, to refuse. A throwing check is a refusal. The dashboard is
   * read-only, so the name is not recorded anywhere.
   */
  | { authorize: (request: IncomingMessage) => boolean | string | Promise<boolean | string> }
  /**
   * No authentication. An explicit, greppable opt-out: write it when something in front of
   * the dashboard already authenticates, never merely to make the startup error go away.
   */
  | false;

/**
 * What a caller the dashboard will not serve is told.
 *
 * The default, `unauthorized`, is honest: a person who mistyped a password is told so. The
 * others are concealment, not access control: they raise the cost of *finding* the page and
 * do nothing against somebody who holds the credential.
 */
export type DashboardRefusal =
  /** `401` (with `WWW-Authenticate` for Basic), `421` for a wrong host, `403` for the rest. */
  | "unauthorized"
  /** Byte-identical to the answer for a path that does not exist. Not usable with Basic auth. */
  | "not-found"
  /** The connection is destroyed with nothing written. Not usable with Basic auth. */
  | "close"
  /** Send them to your sign-in page. Announces that something is here. */
  | { redirect: string; status?: 302 | 303 | 307 | 308 };

/**
 * Which parts of the dashboard exist on this listener.
 *
 * A section switched off here is withheld on the server: its screen is removed and its API
 * answers 404, so the data never leaves the process. Hiding a screen in `<hackerpot-dashboard>`
 * is cosmetic by comparison. Every section is on unless you say otherwise.
 */
export interface DashboardSections {
  /** KPIs, volume, top detections and offenders. */
  overview?: boolean;
  /**
   * The incident feed and each incident's detail. Off, the captured request itself stays in
   * the process: incidents reaching the other screens carry no body and no header but the
   * User-Agent.
   */
  incidents?: boolean;
  /** Distributions, heatmaps, paths, identities. */
  statistics?: boolean;
  /** Per-address attack timelines. */
  sessions?: boolean;
  /** Fingerprints seen from several addresses. */
  actors?: boolean;
  /** Indicators of compromise and the Prometheus exposition. */
  intel?: boolean;
}

/** What is removed from incidents before they reach a browser. */
export interface DashboardRedaction {
  /**
   * Strip credentials: `Authorization`, `Cookie`, API-key and secret-named headers, secret
   * form and JSON fields, and those values wherever a detector quoted them. Default true.
   *
   * On by default even though the page is an operator's: a captured password is a real
   * person's password as often as it is a guess, and a dashboard is screen-shared,
   * screenshotted and left open far more often than a log is read. Turn it off when you
   * need to see what an attacker tried.
   */
  credentials?: boolean;
  /** Show addresses as their `/24` (IPv4) or `/48` (IPv6). Default false. */
  maskIp?: boolean;
}

export interface DashboardOptions {
  /** Port to listen on. Default 9501. Pass 0 for an ephemeral port and read it from `url`. */
  port?: number;
  /**
   * Address to bind. Default `"127.0.0.1"`. Anything else publishes the page, so it requires
   * an explicit `auth` (or an explicit `auth: false`).
   */
  host?: string;
  auth?: DashboardAuth;
  /** How a refused caller is answered. Default `"unauthorized"`. */
  refusal?: DashboardRefusal;
  /** Path the dashboard is served under, e.g. `"/_hackerpot"`. Default `"/"`. */
  basePath?: string;
  /** Shown in the header and the tab title. Default `"hackerpot"`. */
  title?: string;
  /**
   * Which deployment this is. Default the machine's hostname. A dashboard shows one
   * deployment's store; naming it stops a partial picture from looking like a whole one.
   */
  instance?: string;
  /** Links shown in the header: your runbook, your SIEM. */
  links?: ReadonlyArray<{ label: string; href: string }>;
  sections?: DashboardSections;
  redact?: DashboardRedaction;
  /**
   * `Host` header values to answer, compared without the port. On a loopback bind the
   * loopback names are always allowed and this adds to them; it is what defeats DNS
   * rebinding. On a public bind or mounted, it is enforced when given, so a dashboard behind
   * a reverse proxy answers only to its public name. `"*"` disables the check.
   */
  allowedHosts?: readonly string[];
  /** Client addresses or CIDRs allowed to reach the dashboard at all, checked before auth. */
  allowedClients?: readonly string[];
  /**
   * Slowing down repeated wrong credentials. Default on: after `maxAttempts` (5) failures
   * from one address, further attempts are refused for a delay that doubles from `lockoutMs`
   * (1s) up to `maxLockoutMs` (5 min). `false` switches it off.
   */
  authThrottle?: { maxAttempts?: number; lockoutMs?: number; maxLockoutMs?: number } | false;
  /** Concurrent live-feed viewers. Default 16; past it the stream answers 503. */
  maxClients?: number;
  /** Incidents per second pushed to each viewer. Default 100; the surplus is counted and skipped. */
  maxEventsPerSecond?: number;
  /** Called with failures the dashboard absorbs: a source that is down, a viewer's socket error. */
  onError?: (error: unknown) => void;
}

/**
 * Options for `createDashboardHandler`: the listener options without the socket, and `auth`
 * required. Mounted, there is no bind address to inspect, so nothing is assumed about who
 * can reach it.
 */
export type DashboardHandlerOptions = Omit<DashboardOptions, "port" | "host"> & { auth: DashboardAuth };

/** The dashboard as a request handler for a server you already have. */
export interface DashboardRequestHandler {
  (request: IncomingMessage, response: ServerResponse): void;
  /** Live-feed viewers currently connected. */
  readonly clients: number;
  /** Ends every stream and unsubscribes from the source. Does not close your server. */
  close(): Promise<void>;
}

/** A running dashboard with a listener of its own. */
export interface DashboardServer {
  /** The address to open, with the port actually bound. */
  readonly url: string;
  readonly port: number;
  readonly host: string;
  readonly clients: number;
  /** Stops listening, drops every stream, unsubscribes. Idempotent. */
  close(): Promise<void>;
}

/** What the page, and an embedded element, are told about the dashboard they are showing. */
export interface DashboardBootstrap {
  /** Where the API lives, relative to the origin. `""` for a root mount. */
  base: string;
  title: string;
  instance: string;
  /** The package version the handler runs, so an embedded element can detect version skew. */
  version: string;
  sections: Required<DashboardSections>;
  links: Array<{ label: string; href: string }>;
  /** Where the data comes from, e.g. `"this process"` or `"management API at http://10.0.0.5:9500"`. */
  source: string;
  redaction: Required<DashboardRedaction>;
}
