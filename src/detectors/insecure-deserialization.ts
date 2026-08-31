import type { Detection, DetectionContext, Detector } from "./types.js";

export interface InsecureDeserializationOptions {
  score?: number;
  inspectBody?: boolean;
  /** Header names to scan (serialized blobs often ride in cookies). Lowercase. */
  inspectHeaders?: string[];
  respondWith?: string;
}

const MAX_SCAN = 16384;
const DEFAULT_HEADERS = ["cookie", "x-serialized", "viewstate", "__viewstate"];

interface Signature {
  kind: string;
  pattern: RegExp;
}

const SIGNATURES: Signature[] = [
  // Java serialized object — magic bytes 0xAC 0xED 0x00 0x05, base64 "rO0AB".
  { kind: "java-serialized", pattern: /rO0AB[A-Za-z0-9+/]{8,}/ },
  // PHP serialized OBJECT (the injection-dangerous form): O:<len>:"Class":
  { kind: "php-serialized-object", pattern: /\bO:\d+:"[^"]+":\d+:\{/ },
  // .NET BinaryFormatter — base64 "AAEAAAD/////".
  { kind: "dotnet-binaryformatter", pattern: /AAEAAAD\/\/\/\/\/[A-Za-z0-9+/]{8,}/ },
  // Python pickle markers (opcodes / dangerous reduce targets).
  { kind: "python-pickle", pattern: /(c__builtin__\n|cposix\nsystem|cos\nsystem|__reduce__)/ },
  // Ruby Marshal — version bytes \x04\x08, base64 "BAg".
  { kind: "ruby-marshal", pattern: /\bBAg[A-Za-z0-9+/]{8,}=*(?:$|[&;"'\s])/ },
  // Node node-serialize RCE marker.
  //
  // ONLY the marker. This also carried a bare `\}\(\)\s*"` alternative — any `}()` at
  // the end of a JSON string — which could not indicate the attack it names: the
  // `node-serialize` exploit works because `unserialize()` evals the payload that
  // FOLLOWS `_$$ND_FUNC$$_`, so a value without the marker is not a node-serialize
  // payload at all. It did fire on ordinary content, at score 9 — near enough the
  // block threshold that a handful of requests blocks the client. A template or
  // config API storing `{"transform":"function(v){return v*2}()"}` is the whole
  // pattern, and in middleware mode that is a real user being blocked by a signature
  // that had no true positives of its own to lose.
  { kind: "node-serialize", pattern: /_\$\$ND_FUNC\$\$_/ },
];

function scan(raw: string): Signature | undefined {
  const value = raw.length > MAX_SCAN ? raw.slice(0, MAX_SCAN) : raw;
  return SIGNATURES.find((s) => s.pattern.test(value));
}

/**
 * Insecure deserialization: a serialized-object payload for Java, PHP, .NET,
 * Python, Ruby, or Node in the body, a header (cookies are a classic carrier), or
 * a query value. Deserializing attacker-controlled objects is a top RCE class, and
 * these serialization formats have distinctive magic bytes / markers, so this is a
 * high-severity, low-false-positive signal.
 */
export function insecureDeserializationDetector(options: InsecureDeserializationOptions = {}): Detector {
  const score = options.score ?? 9;
  const inspectBody = options.inspectBody ?? true;
  const inspectHeaders = options.inspectHeaders ?? DEFAULT_HEADERS;

  return {
    id: "insecure-deserialization",
    description: "A serialized-object payload (Java/PHP/.NET/Python/Ruby/Node) — deserialization RCE probe",
    needsBody: inspectBody,
    inspect(ctx: DetectionContext): Detection | undefined {
      const targets: Array<{ location: string; value: string }> = [];
      for (const [key, value] of Object.entries(ctx.query)) targets.push({ location: `query.${key}`, value });
      for (const name of inspectHeaders) {
        const raw = ctx.headers[name];
        const value = Array.isArray(raw) ? raw.join(" ") : raw;
        if (value) targets.push({ location: `header.${name}`, value });
      }
      if (inspectBody && ctx.body) targets.push({ location: "body", value: ctx.body });

      for (const target of targets) {
        const sig = scan(target.value);
        if (!sig) continue;
        const detection: Detection = {
          detectorId: "insecure-deserialization",
          reason: `Insecure deserialization — ${sig.kind} payload in ${target.location}`,
          score,
          metadata: { kind: sig.kind, location: target.location, sample: target.value.slice(0, 200) },
        };
        if (options.respondWith) detection.respondWith = options.respondWith;
        return detection;
      }
      return undefined;
    },
  };
}
