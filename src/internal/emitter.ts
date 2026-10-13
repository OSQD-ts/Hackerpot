// Kept identical in hackerpot and bothandlerjs. Change both, or neither.

/**
 * A small typed event emitter, isolated on purpose.
 *
 * Not `node:events`. Listeners here run on the request path — a dashboard subscribing to
 * results, a notification sink, an operator's own logging — and `EventEmitter` calls them
 * synchronously in registration order, so one that throws aborts the loop: every listener
 * registered after it never hears the event, and the throw surfaces inside whatever was
 * emitting. That is the same failure the detector pipeline already guards against, and for
 * the same reason: a subscriber is somebody else's code.
 *
 * So each listener is wrapped. It can only break itself, the failure is reported on the
 * owner's error channel, and the remaining listeners still hear the event. A listener that
 * hands back a rejected promise is caught too, which a `try` around a call is not.
 */
export type Listener<T> = (payload: T) => void;

export class Emitter<Events extends Record<string, unknown>> {
  private readonly listeners = new Map<keyof Events, Set<Listener<never>>>();

  constructor(private readonly onError: (error: unknown, event: string) => void = () => undefined) {}

  /** Registers a listener and returns the way to remove it. */
  on<K extends keyof Events & string>(event: K, listener: Listener<Events[K]>): () => void {
    let set = this.listeners.get(event);
    if (set === undefined) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(listener as Listener<never>);
    return () => {
      set.delete(listener as Listener<never>);
    };
  }

  off<K extends keyof Events & string>(event: K, listener: Listener<Events[K]>): void {
    this.listeners.get(event)?.delete(listener as Listener<never>);
  }

  /** True when anything is listening, so a caller can skip building a payload nobody wants. */
  has<K extends keyof Events & string>(event: K): boolean {
    const set = this.listeners.get(event);
    return set !== undefined && set.size > 0;
  }

  emit<K extends keyof Events & string>(event: K, payload: Events[K]): void {
    const set = this.listeners.get(event);
    if (set === undefined || set.size === 0) return;
    // A copy, so a listener that unsubscribes itself (or another) while this runs cannot
    // change the set underneath the loop.
    for (const listener of [...set]) {
      try {
        const result = (listener as Listener<Events[K]>)(payload) as unknown;
        // A listener declared `async` returns a promise; an unhandled rejection from it
        // would terminate the process by default, which is not something a subscriber
        // should be able to do to the process it runs in.
        if (typeof (result as { then?: unknown } | undefined)?.then === "function") {
          void (result as Promise<unknown>).catch((error: unknown) => this.onError(error, event));
        }
      } catch (error) {
        this.onError(error, event);
      }
    }
  }

  removeAll(): void {
    this.listeners.clear();
  }
}
