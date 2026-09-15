import WebSocket from "ws";
import type { HoneypotEngine } from "../core.js";
import type { IncidentBroker } from "../management/broker.js";
import { renderMetrics } from "../management/metrics.js";
import { computeActors, computeIoc, computeSessions, computeStats, getIncident, listIncidents } from "../management/rest.js";
import type { ActorGroup, AttackSession, IocEntry, StatsSummary } from "../management/rest.js";
import type { ManagementServer } from "../management/server.js";
import type { Incident } from "../management/types.js";
import type { HitStore } from "../types.js";

/**
 * Where a dashboard reads from.
 *
 * Two kinds, one interface. An **in-process** source reads the store and hears hits from
 * the engine in the same process: the library use, and the standalone service's own
 * `[dashboard]`. A **remote** source talks to a running HackerPot's management API over
 * HTTP and its live WebSocket: the dashboard as a separate service beside the stack, which
 * holds the API key itself so the browser never sees it.
 *
 * Every method answers in the management API's own shapes, so the browser code is the same
 * whichever kind is behind it.
 */
export interface DashboardSource {
  /** One line for the header, e.g. `"this process"`. */
  readonly description: string;
  listIncidents(query: URLSearchParams): Promise<Incident[]>;
  getIncident(id: string): Promise<Incident | undefined>;
  stats(): Promise<StatsSummary>;
  sessions(ip?: string): Promise<AttackSession[]>;
  actors(fingerprint?: string): Promise<ActorGroup[]>;
  ioc(minScore: number): Promise<IocEntry[]>;
  /** Prometheus text exposition. */
  metrics(): Promise<string>;
  /** Every new incident, as it happens. Returns the way to stop. */
  subscribe(listener: (incident: Incident) => void): () => void;
  /** Releases connections the source opened. */
  close?(): Promise<void>;
}

/** The read half every in-process source shares: the store, through the management API's own functions. */
function storeReads(store: HitStore): Pick<DashboardSource, "listIncidents" | "getIncident" | "stats" | "sessions" | "actors" | "ioc"> {
  return {
    listIncidents: (query) => listIncidents(store, query),
    getIncident: (id) => getIncident(store, id),
    stats: () => computeStats(store),
    sessions: (ip) => computeSessions(store, ip),
    actors: (fingerprint) => computeActors(store, fingerprint),
    ioc: (minScore) => computeIoc(store, minScore),
  };
}

export interface StoreSourceOptions {
  store: HitStore;
  /** How new incidents are heard: a broker, an engine, or any `subscribe` function. */
  subscribe: (listener: (incident: Incident) => void) => () => void;
  /**
   * Prometheus text. Default: derived from the store, so incidents recorded before the
   * dashboard started count too. A dashboard reads it on demand, not on a scrape interval.
   */
  metrics?: () => Promise<string> | string;
  description?: string;
}

/** A store plus a way to hear new incidents. The building block the other in-process sources use. */
export function storeSource(options: StoreSourceOptions): DashboardSource {
  return {
    description: options.description ?? "this process",
    ...storeReads(options.store),
    metrics: async () => (options.metrics !== undefined ? options.metrics() : renderMetrics(options.store)),
    subscribe: options.subscribe,
  };
}

/**
 * An engine in this process. Hears every hit the engine records, plus anything published to
 * it with `engine.publish` (the standalone service publishes its SSH, SMTP, FTP and Telnet
 * hits there).
 */
export function engineSource(engine: HoneypotEngine): DashboardSource {
  return storeSource({
    store: engine.store,
    subscribe: (listener) => engine.subscribe(listener),
    // The live gauges only the engine knows, beside the store's counts.
    metrics: async () => renderMetrics(engine.store, { active_blocks: (await engine.blocklist.size?.()) ?? 0, tracked_ips: engine.registry.size }),
  });
}

/** A management server in this process: its store, its broker, and its `/metrics` counters. */
export function managementServerSource(server: ManagementServer, store: HitStore): DashboardSource {
  return storeSource({ store, subscribe: (listener) => server.broker.subscribe(listener), metrics: () => server.metricsText() });
}

/** A broker and the store it describes. */
export function brokerSource(broker: IncidentBroker, store: HitStore): DashboardSource {
  return storeSource({ store, subscribe: (listener) => broker.subscribe(listener) });
}

export interface ManagementApiSourceOptions {
  /** The management API's base URL, e.g. `http://10.0.0.5:9500`. */
  url: string;
  /** One of the management API's `api_keys`. Held here; never sent to a browser. */
  apiKey: string;
  /** Per-request deadline. Default 10 seconds. */
  timeoutMs?: number;
  /** Called when the live connection drops or a reconnect fails. */
  onError?: (error: unknown) => void;
}

/** Longest a live connection waits before trying again, however many attempts have failed. */
const MAX_RECONNECT_MS = 30_000;

/**
 * A HackerPot running somewhere else, read through its management API.
 *
 * REST reads are made per request with the key in `Authorization`. The live feed is one
 * WebSocket to `/stream`, opened when the first viewer subscribes and closed when the last
 * leaves, and reopened with backoff when it drops, so one dashboard holds one connection
 * however many browsers are watching.
 */
export function managementApiSource(options: ManagementApiSourceOptions): DashboardSource {
  const base = new URL(options.url);
  if (base.protocol !== "http:" && base.protocol !== "https:") throw new Error(`management API URL must be http or https: ${options.url}`);
  if (options.apiKey === "") throw new Error("management API source needs an API key");
  const root = base.href.replace(/\/+$/, "");
  const timeoutMs = options.timeoutMs ?? 10_000;
  const listeners = new Set<(incident: Incident) => void>();
  let socket: WebSocket | undefined;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let attempts = 0;
  let closed = false;

  async function get(path: string, accept = "application/json"): Promise<Response> {
    const response = await fetch(`${root}${path}`, {
      headers: { authorization: `Bearer ${options.apiKey}`, accept },
      signal: AbortSignal.timeout(timeoutMs),
    });
    return response;
  }

  async function json<T>(path: string, notFoundAs?: T): Promise<T> {
    const response = await get(path);
    if (response.status === 404 && notFoundAs !== undefined) {
      await response.body?.cancel();
      return notFoundAs;
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`management API answered ${response.status} for ${path}`);
    }
    return (await response.json()) as T;
  }

  function connect(): void {
    if (closed || socket !== undefined || listeners.size === 0) return;
    const wsUrl = `${root.replace(/^http/, "ws")}/stream`;
    const ws = new WebSocket(wsUrl, { headers: { authorization: `Bearer ${options.apiKey}` }, handshakeTimeout: timeoutMs });
    socket = ws;
    ws.on("open", () => {
      attempts = 0;
    });
    ws.on("message", (data) => {
      let message: { type?: string; incident?: Incident };
      try {
        message = JSON.parse(String(data)) as { type?: string; incident?: Incident };
      } catch {
        return;
      }
      if (message.type !== "incident" || message.incident === undefined) return;
      for (const listener of listeners) {
        try {
          listener(message.incident);
        } catch (err) {
          options.onError?.(err);
        }
      }
    });
    ws.on("error", (err) => options.onError?.(err));
    ws.on("close", () => {
      socket = undefined;
      if (closed || listeners.size === 0) return;
      attempts += 1;
      const delay = Math.min(MAX_RECONNECT_MS, 500 * 2 ** Math.min(attempts, 10));
      retry = setTimeout(() => {
        retry = undefined;
        connect();
      }, delay);
      retry.unref();
    });
  }

  function disconnect(): void {
    if (retry !== undefined) clearTimeout(retry);
    retry = undefined;
    socket?.terminate();
    socket = undefined;
  }

  return {
    description: `management API at ${base.host}`,
    listIncidents: async (query) => (await json<{ incidents: Incident[] }>(`/incidents?${query.toString()}`)).incidents,
    getIncident: async (id) => (await json<{ incident?: Incident }>(`/incidents/${encodeURIComponent(id)}`, {})).incident,
    stats: () => json<StatsSummary>("/stats"),
    sessions: async (ip) =>
      ip === undefined ? (await json<{ sessions: AttackSession[] }>("/sessions")).sessions : [(await json<{ session?: AttackSession }>(`/sessions/${encodeURIComponent(ip)}`, {})).session].filter((s): s is AttackSession => s !== undefined),
    actors: async (fingerprint) =>
      fingerprint === undefined
        ? (await json<{ actors: ActorGroup[] }>("/actors")).actors
        : [(await json<{ actor?: ActorGroup }>(`/actors/${encodeURIComponent(fingerprint)}`, {})).actor].filter((a): a is ActorGroup => a !== undefined),
    ioc: async (minScore) => (await json<{ indicators: IocEntry[] }>(`/ioc?min_score=${minScore}`)).indicators,
    metrics: async () => {
      const response = await get("/metrics", "text/plain");
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error(`management API answered ${response.status} for /metrics`);
      }
      return response.text();
    },
    subscribe(listener) {
      listeners.add(listener);
      connect();
      return () => {
        listeners.delete(listener);
        if (listeners.size === 0) disconnect();
      };
    },
    async close() {
      closed = true;
      listeners.clear();
      disconnect();
    },
  };
}

/** Anything a dashboard can be pointed at, turned into a source. */
export type DashboardSourceLike = DashboardSource | HoneypotEngine | { engine: HoneypotEngine };

export function toDashboardSource(value: DashboardSourceLike): DashboardSource {
  if ("listIncidents" in value && "subscribe" in value && "metrics" in value) return value;
  if ("engine" in value) return engineSource(value.engine);
  return engineSource(value);
}
