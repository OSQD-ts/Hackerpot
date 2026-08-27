import type { Detection, DetectionContext, Detector } from "./types.js";

export interface GraphqlAbuseOptions {
  score?: number;
  /** Max brace-nesting depth in a GraphQL document before it's treated as a resource-exhaustion attempt. Default 12. */
  maxDepth?: number;
  /** Inspect the request body (GraphQL is usually POSTed as JSON). Default true. */
  inspectBody?: boolean;
  respondWith?: string;
}

const MAX_SCAN = 16384;
// Introspection tokens — how an attacker dumps your whole schema. Very GraphQL-specific.
const INTROSPECTION = /\b__schema\b|\bIntrospectionQuery\b|__type\s*\(/;

function maxBraceDepth(s: string): number {
  let depth = 0;
  let max = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "{") {
      depth += 1;
      if (depth > max) max = depth;
    } else if (c === "}") {
      if (depth > 0) depth -= 1;
    }
  }
  return max;
}

/**
 * GraphQL abuse: a schema-introspection query (`__schema` / `IntrospectionQuery` —
 * how an attacker maps your entire API), or a pathologically deep nested query
 * (a resource-exhaustion / DoS vector unique to GraphQL). Introspection is matched
 * anywhere (the tokens are GraphQL-specific); depth is only judged on requests that
 * actually look like GraphQL, to avoid counting braces in unrelated JSON.
 */
export function graphqlAbuseDetector(options: GraphqlAbuseOptions = {}): Detector {
  const score = options.score ?? 7;
  const maxDepth = options.maxDepth ?? 12;
  const inspectBody = options.inspectBody ?? true;

  return {
    id: "graphql-abuse",
    description: "GraphQL schema introspection or a pathologically deep nested query",
    needsBody: inspectBody,
    inspect(ctx: DetectionContext): Detection | undefined {
      const parts: string[] = [ctx.path];
      for (const value of Object.values(ctx.query)) parts.push(value);
      if (inspectBody && ctx.body) parts.push(ctx.body);
      const blob = parts.join("\n").slice(0, MAX_SCAN);

      const isGraphql = /graphql/i.test(ctx.path) || /"query"\s*:|"mutation"\s*:|\b(query|mutation)\s*[({]/.test(blob);

      const fire = (kind: string): Detection => {
        const detection: Detection = { detectorId: "graphql-abuse", reason: `GraphQL abuse — ${kind}`, score, metadata: { kind } };
        if (options.respondWith) detection.respondWith = options.respondWith;
        return detection;
      };

      if (INTROSPECTION.test(blob)) return fire("schema introspection");
      if (isGraphql) {
        const depth = maxBraceDepth(blob);
        if (depth > maxDepth) return fire(`deeply nested query (depth ${depth} > ${maxDepth})`);
      }
      return undefined;
    },
  };
}
