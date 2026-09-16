/**
 * Where the time comes from.
 *
 * Every window this library keeps — the per-address activity window, the audit's buckets,
 * a block's expiry, a webhook's throttle, a DNS answer's lifetime — is a comparison against
 * "now". Reading the system clock directly in each of them makes the behaviour that matters
 * most untestable without sleeping: a test for "this is forgotten after an hour" either
 * waits an hour or asserts nothing. Injecting the clock turns those into ordinary
 * assertions, and costs a property access in production.
 *
 * The unit is epoch milliseconds, the same thing `Date.now()` returns, so a clock is a
 * drop-in for it. Adapted from bothandlerjs.
 */
export interface Clock {
  now(): number;
}

export const systemClock: Clock = { now: () => Date.now() };

/**
 * A clock that only moves when a test moves it.
 *
 * Deterministic in both directions: nothing ages without `advance`, and nothing races a
 * real timer. Exported from the package so callers can test their own detectors and
 * response actions against the engine the same way this library tests its own.
 */
export class ManualClock implements Clock {
  private current: number;

  constructor(start: number | Date = 0) {
    this.current = start instanceof Date ? start.getTime() : start;
  }

  now(): number {
    return this.current;
  }

  /** Moves time forward. A negative argument is refused: a window that ran backwards would report nonsense. */
  advance(ms: number): void {
    if (ms < 0) throw new RangeError("a clock cannot be advanced backwards");
    this.current += ms;
  }

  set(at: number | Date): void {
    this.current = at instanceof Date ? at.getTime() : at;
  }
}
