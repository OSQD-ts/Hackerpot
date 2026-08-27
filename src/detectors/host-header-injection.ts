import type { Detection, DetectionContext, Detector } from "./types.js";

export interface HostHeaderInjectionOptions {
  score?: number;
  /**
   * Your site's canonical hostnames. When set, a Host / X-Forwarded-Host outside
   * this list is flagged as spoofing. Lowercase, without port. When omitted, only
   * structurally-malformed Host headers are flagged (the X-Forwarded-Host check
   * needs this list, since a differing X-Forwarded-Host is normal behind a proxy).
   */
  expectedHosts?: string[];
  respondWith?: string;
}

// Characters that never appear in a valid host[:port] / IPv6 literal.
const INVALID_HOST = /[^a-z0-9.\-:_[\]]/i;

function values(ctx: DetectionContext, name: string): string[] {
  const raw = ctx.headers[name];
  if (raw === undefined) return [];
  return Array.isArray(raw) ? raw : [raw];
}

function bareHost(value: string): string {
  return value.trim().toLowerCase().replace(/:\d+$/, "");
}

/**
 * Host-header injection: manipulating `Host` (or `X-Forwarded-Host`) to poison
 * password-reset links, absolute URLs, or a web cache. Structurally-invalid or
 * duplicated Host headers are always flagged; supplying `expectedHosts` additionally
 * flags any Host / X-Forwarded-Host outside your canonical set — the precise check,
 * since a differing `X-Forwarded-Host` is normal behind a proxy and can't be judged
 * without knowing your real hostnames.
 */
export function hostHeaderInjectionDetector(options: HostHeaderInjectionOptions = {}): Detector {
  const score = options.score ?? 6;
  // Normalize the expected set exactly as incoming hosts are (lowercased, port stripped)
  // so a canonical entry written with a port still matches the port-stripped Host.
  const expected = options.expectedHosts?.length ? new Set(options.expectedHosts.map((h) => bareHost(h))) : undefined;

  return {
    id: "host-header-injection",
    description: "A malformed, duplicated, or off-allowlist Host / X-Forwarded-Host header",
    inspect(ctx: DetectionContext): Detection | undefined {
      const hostHeaders = values(ctx, "host");
      const xfHost = values(ctx, "x-forwarded-host");

      const fire = (reason: string, kind: string): Detection => {
        const detection: Detection = { detectorId: "host-header-injection", reason, score, metadata: { kind } };
        if (options.respondWith) detection.respondWith = options.respondWith;
        return detection;
      };

      // Duplicate Host headers — request smuggling / cache-poisoning setup.
      if (hostHeaders.length > 1) return fire(`Multiple Host headers: ${hostHeaders.join(", ").slice(0, 120)}`, "duplicate-host");
      // Structurally-invalid Host (embedded whitespace, @, /, absolute-form, injected chars).
      for (const h of hostHeaders) {
        if (INVALID_HOST.test(h) || /^https?:\/\//i.test(h)) return fire(`Malformed Host header: ${h.slice(0, 120)}`, "malformed-host");
      }

      // With a canonical set, anything off it (Host or X-Forwarded-Host) is spoofing.
      if (expected) {
        for (const h of hostHeaders) {
          if (h && !expected.has(bareHost(h))) return fire(`Host "${bareHost(h)}" is not an expected hostname`, "unexpected-host");
        }
        for (const h of xfHost) {
          if (h && !expected.has(bareHost(h))) return fire(`X-Forwarded-Host "${bareHost(h)}" is not an expected hostname`, "unexpected-forwarded-host");
        }
      }
      return undefined;
    },
  };
}
