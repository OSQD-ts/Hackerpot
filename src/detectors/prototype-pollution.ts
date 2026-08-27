import type { Detection, DetectionContext, Detector } from "./types.js";

export interface PrototypePollutionOptions {
  score?: number;
  /** Scan the request body. Default true. */
  inspectBody?: boolean;
  respondWith?: string;
}

const MAX_SCAN = 16384;
// `__proto__` is a magic key that never appears in legitimate user input; and
// `constructor` immediately accessing `prototype` (via . or []) is the other vector.
const PROTO = /__proto__/;
// `constructor.prototype` / `constructor['prototype']` / `constructor[prototype]` (JS access),
// and `"constructor": { ... "prototype"` (the JSON-nesting form a merge would walk).
const CONSTRUCTOR_PROTO = /constructor\s*(\[\s*['"]?prototype|\.\s*prototype)/i;
const CONSTRUCTOR_PROTO_JSON = /["']constructor["']\s*:\s*\{[^{}]{0,300}?["']prototype["']/i;

function scan(raw: string): string | undefined {
  const value = raw.length > MAX_SCAN ? raw.slice(0, MAX_SCAN) : raw;
  let decoded = value;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    /* keep raw */
  }
  for (const candidate of [value, decoded]) {
    if (PROTO.test(candidate)) return "__proto__ key";
    if (CONSTRUCTOR_PROTO.test(candidate) || CONSTRUCTOR_PROTO_JSON.test(candidate)) return "constructor.prototype access";
  }
  return undefined;
}

/**
 * Prototype pollution: an attempt to inject `__proto__` (or `constructor.prototype`)
 * into a query parameter or JSON body so a naive merge/assign writes onto
 * Object.prototype — a Node-specific vector that escalates from a config tweak to
 * RCE. Matched as a key/access, so an ordinary sentence mentioning "constructor"
 * or "prototype" doesn't trip it (`__proto__` itself is never legitimate input).
 */
export function prototypePollutionDetector(options: PrototypePollutionOptions = {}): Detector {
  const score = options.score ?? 8;
  const inspectBody = options.inspectBody ?? true;

  return {
    id: "prototype-pollution",
    description: "A __proto__ / constructor.prototype key in a query or JSON body",
    needsBody: inspectBody,
    inspect(ctx: DetectionContext): Detection | undefined {
      const targets: Array<{ location: string; value: string }> = [];
      for (const [key, value] of Object.entries(ctx.query)) {
        targets.push({ location: `query-key.${key}`, value: key });
        targets.push({ location: `query.${key}`, value });
      }
      if (inspectBody && ctx.body) targets.push({ location: "body", value: ctx.body });

      for (const target of targets) {
        const kind = scan(target.value);
        if (!kind) continue;
        const detection: Detection = {
          detectorId: "prototype-pollution",
          reason: `Prototype pollution — ${kind} in ${target.location}`,
          score,
          metadata: { location: target.location, sample: target.value.slice(0, 200) },
        };
        if (options.respondWith) detection.respondWith = options.respondWith;
        return detection;
      }
      return undefined;
    },
  };
}
