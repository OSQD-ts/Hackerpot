import { apiUrl, readError } from "./api.js";
import { app } from "./app.js";
import { SECTIONS } from "./boot.js";
import { explainFailure, isIncident, reconnectDelay } from "./query.js";
import { state, type StreamState } from "./store.js";

/**
 * The live feed: one `EventSource` on `${base}/api/events`.
 *
 * `EventSource` reconnects by itself after a dropped connection, and while it does its
 * `readyState` is CONNECTING. What it does not do is retry after a response that was not an
 * event stream at all (a 401, a 503 because this dashboard already has its maximum of
 * viewers, a 404 because the section is off): it closes for good. So a CLOSED stream is
 * reopened here with backoff, and one request is made to find out *why* it closed, because
 * "reconnecting" forever is indistinguishable from a server that has gone away, and a
 * refused password is not something waiting will fix.
 *
 * The server does not replay missed frames, so any interruption is followed by a reload of
 * the corpus as soon as the stream says hello again. The page never quietly shows a
 * picture with a hole in it.
 */

let source: EventSource | undefined;
let retry: ReturnType<typeof setTimeout> | undefined;
let attempts = 0;
let interrupted = false;
let wanted = false;

/** Whether this dashboard has a live feed at all. The server answers 404 for `/api/events` otherwise. */
export function streamAvailable(): boolean {
  return SECTIONS.incidents || SECTIONS.overview;
}

function setStream(next: StreamState, detail: string): void {
  state.stream = next;
  state.streamDetail = detail;
  app.drawStatus();
}

function parse(event: Event): unknown {
  try {
    return JSON.parse(String((event as MessageEvent).data));
  } catch {
    return undefined;
  }
}

export function connectStream(): void {
  wanted = true;
  if (!streamAvailable()) {
    setStream("off", "no live feed on this dashboard");
    return;
  }
  if (source !== undefined || retry !== undefined) return;
  open();
}

function open(): void {
  const stream = new EventSource(apiUrl("/api/events"));
  source = stream;
  setStream("connecting", "connecting");

  stream.addEventListener("hello", () => {
    attempts = 0;
    app.showFailure("/api/events", undefined);
    setStream("live", "live");
    if (interrupted) {
      interrupted = false;
      void app.refresh();
    }
  });

  stream.addEventListener("incident", (event) => {
    const incident = parse(event);
    if (isIncident(incident)) app.ingest(incident);
  });

  // This browser fell behind and the server dropped frames rather than queue them.
  stream.addEventListener("lagged", (event) => {
    const dropped = Number((parse(event) as { dropped?: unknown } | undefined)?.dropped);
    if (dropped > 0) {
      state.dropped += dropped;
      app.drawNotice();
    }
  });

  // The per-viewer rate limit skipped frames during a burst.
  stream.addEventListener("skipped", (event) => {
    const skipped = Number((parse(event) as { skipped?: unknown } | undefined)?.skipped);
    if (skipped > 0) {
      state.skipped += skipped;
      app.drawNotice();
    }
  });

  stream.addEventListener("error", () => {
    if (source !== stream) return;
    interrupted = true;
    if (stream.readyState !== EventSource.CLOSED) {
      setStream("connecting", "reconnecting");
      return;
    }
    stream.close();
    source = undefined;
    const delay = reconnectDelay(attempts++);
    setStream("down", `reconnecting in ${Math.round(delay / 1000)}s`);
    void diagnose();
    retry = setTimeout(() => {
      retry = undefined;
      if (wanted) open();
    }, delay);
  });
}

/**
 * Why the stream closed. One ordinary request to the same URL, aborted as soon as its
 * status is known, so it holds a viewer slot for no longer than the headers take.
 */
async function diagnose(): Promise<void> {
  const controller = new AbortController();
  try {
    const response = await fetch(apiUrl("/api/events"), { credentials: "same-origin", cache: "no-store", signal: controller.signal, headers: { accept: "text/event-stream" } });
    if (response.ok) return;
    const message = await readError(response);
    app.showFailure("/api/events", explainFailure(response.status, "/api/events", message));
  } catch {
    // Unreachable: the refresh that follows the reconnect reports it with more context.
  } finally {
    controller.abort();
  }
}

/** Closes the feed and stops retrying, keeping everything drawn. */
export function suspendStream(): void {
  wanted = false;
  if (retry !== undefined) clearTimeout(retry);
  retry = undefined;
  if (source !== undefined) {
    source.close();
    source = undefined;
    interrupted = true;
  }
  if (streamAvailable()) setStream("paused", "live feed paused");
}
