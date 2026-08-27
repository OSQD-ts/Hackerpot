import type { Detection, DetectionContext, Detector } from "./types.js";

export interface NosqlInjectionOptions {
  score?: number;
  /** Scan the request body (JSON operator-injection). Default true. */
  inspectBody?: boolean;
  respondWith?: string;
}

// MongoDB query/update operators used in NoSQL injection (auth bypass, blind extraction, $where JS).
const OPERATORS = "ne|gt|gte|lt|lte|in|nin|where|regex|exists|or|and|nor|not|expr|elemmatch|all|function|jsonschema";

// `param[$ne]=` — the bracketed-operator form that Express/qs turns into a nested object.
const KEY_BRACKET = new RegExp(`\\[\\$(${OPERATORS})\\]`, "i");
// `"$ne":` / `'$where':` — a Mongo operator used as a JSON key in a value or body.
const JSON_OP_KEY = new RegExp(`["']\\$(${OPERATORS})["']\\s*:`, "i");

const MAX_SCAN = 16384;
function cap(value: string): string {
  return value.length > MAX_SCAN ? value.slice(0, MAX_SCAN) : value;
}

/**
 * NoSQL (MongoDB) operator injection: a query parameter smuggling an operator via
 * the `param[$ne]=` bracket form, or a JSON value/body with a `"$ne"`/`"$where"`/
 * `"$regex"` operator key. The classic case is an auth bypass —
 * `{"username":"admin","password":{"$ne":null}}` — but the same shapes drive blind
 * data extraction and `$where` JavaScript execution. Matched precisely (the
 * operator must appear as a bracketed key or a JSON key, never as bare text), so a
 * value that merely contains a `$` does not trip it.
 */
export function nosqlInjectionDetector(options: NosqlInjectionOptions = {}): Detector {
  const score = options.score ?? 9;
  const inspectBody = options.inspectBody ?? true;

  return {
    id: "nosql-injection",
    description: "Request smuggles a MongoDB operator ($ne/$gt/$where/…) via a query key or JSON body",
    needsBody: inspectBody,
    inspect(ctx: DetectionContext): Detection | undefined {
      const fire = (kind: string, location: string, sample: string): Detection => {
        const detection: Detection = {
          detectorId: "nosql-injection",
          reason: `NoSQL operator injection — ${kind} in ${location}`,
          score,
          metadata: { location, sample: sample.slice(0, 200) },
        };
        if (options.respondWith) detection.respondWith = options.respondWith;
        return detection;
      };

      for (const [key, value] of Object.entries(ctx.query)) {
        if (KEY_BRACKET.test(key)) return fire("operator in query key", `query.${key}`, key);
        if (JSON_OP_KEY.test(cap(value))) return fire("operator key in query value", `query.${key}`, value);
      }
      if (inspectBody && ctx.body && JSON_OP_KEY.test(cap(ctx.body))) return fire("operator key in body", "body", ctx.body);

      return undefined;
    },
  };
}
