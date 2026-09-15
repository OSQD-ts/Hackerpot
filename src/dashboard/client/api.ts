import { API } from "./boot.js";
import { isEmbedded } from "./dom.js";
import { withToken } from "./query.js";

/**
 * The page's one way of talking to its server: same-origin `GET`s under `${base}/api`.
 *
 * `credentials: "same-origin"`, so whatever authenticated the page (a Basic prompt, a
 * session cookie your `authorize` reads) authenticates its requests too, and nothing is
 * ever sent to another origin. The CSP says `connect-src 'self'` as well; this is the half
 * of that promise the page keeps without being made to.
 */

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly endpoint: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/**
 * The token the page was opened with, carried onto its own requests. Not when embedded:
 * a `?token=` in the host page's address is not this dashboard's to pick up and send.
 */
const token = ((): string => {
  if (typeof location === "undefined") return "";
  try {
    return isEmbedded() ? "" : (new URLSearchParams(location.search).get("token") ?? "");
  } catch {
    return "";
  }
})();

export function apiUrl(path: string): string {
  return withToken(`${API}${path}`, token);
}

/** The endpoint as a person reads it, without the query string. */
export function endpointName(path: string): string {
  return path.split("?")[0] ?? path;
}

/** The server's `{ error }`, or the first line of a text body, or nothing. */
export async function readError(response: Response): Promise<string> {
  const text = await response.text().catch(() => "");
  try {
    const parsed = JSON.parse(text) as { error?: unknown };
    if (typeof parsed.error === "string") return parsed.error;
  } catch {
    /* not JSON */
  }
  return (text.split("\n").find((line) => line.trim() !== "") ?? "").slice(0, 300);
}

async function request(path: string, accept: string): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(apiUrl(path), { credentials: "same-origin", cache: "no-store", headers: { accept } });
  } catch (error) {
    throw new ApiError(0, endpointName(path), error instanceof Error ? error.message : String(error));
  }
  if (!response.ok) throw new ApiError(response.status, endpointName(path), await readError(response));
  return response;
}

export async function getJson<T>(path: string): Promise<T> {
  const response = await request(path, "application/json");
  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError(response.status, endpointName(path), "the answer was not JSON");
  }
}

export async function getText(path: string): Promise<string> {
  return (await request(path, "text/plain")).text();
}

export function asApiError(error: unknown, path: string): ApiError {
  return error instanceof ApiError ? error : new ApiError(0, endpointName(path), error instanceof Error ? error.message : String(error));
}
