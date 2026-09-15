/**
 * Settles with `work`, or rejects with a timeout error after `ms`.
 *
 * Detection runs inline on the request path, so an unbounded await is an availability
 * bug: one custom detector waiting on a stalled service held every request open. The
 * underlying promise cannot be cancelled, but its late result is ignored and its late
 * rejection is already handled here, so neither can surface as an unhandled rejection.
 * Adapted from bothandlerjs, which resolves to a fallback instead; here the timeout is an
 * error so it reaches `onError`.
 */
export function withDeadline<T>(work: PromiseLike<T>, ms: number, what: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${what} did not finish within ${ms}ms`)), ms);
    // A pending detection timer must never be what keeps a process alive.
    timer.unref();
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
