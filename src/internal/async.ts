// Kept identical in hackerpot and bothandlerjs. Change both, or neither.

/**
 * Deadlines for work on the request path.
 *
 * Detection runs inline, so an unbounded await is an availability bug: a slow reverse-DNS
 * lookup, a stalled Redis round-trip or a custom detector waiting on a service that stopped
 * answering would each hold every response open. The underlying promise cannot be cancelled —
 * JavaScript has no such mechanism — but its late result is ignored and its late rejection is
 * handled here, so neither can surface as an unhandled rejection.
 *
 * Two shapes, for the two things a caller can want from a timeout: a value to carry on with
 * (`withTimeout`), or an error that reaches an error channel (`withDeadline`).
 */

/** Settles with `work`, or resolves to `fallback` if it takes longer than `ms`. A non-positive or non-finite `ms` waits for ever. */
export function withTimeout<T>(work: Promise<T>, ms: number, fallback: T): Promise<T> {
  if (!Number.isFinite(ms) || ms <= 0) return work;
  return new Promise<T>((resolve) => {
    const timer = setTimeout(() => resolve(fallback), ms);
    unref(timer);
    work.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        clearTimeout(timer);
        resolve(fallback);
      },
    );
  });
}

/** Settles with `work`, or rejects naming `what` if it takes longer than `ms`. A non-positive or non-finite `ms` waits for ever. */
export function withDeadline<T>(work: PromiseLike<T>, ms: number, what: string): Promise<T> {
  if (!Number.isFinite(ms) || ms <= 0) return Promise.resolve(work);
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${what} did not finish within ${ms}ms`)), ms);
    unref(timer);
    work.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

/** A pending deadline must never be what keeps a process, a CLI or a serverless invocation alive. Not every runtime has `unref`. */
function unref(timer: ReturnType<typeof setTimeout>): void {
  (timer as { unref?: () => void }).unref?.();
}
