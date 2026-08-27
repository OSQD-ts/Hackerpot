import type { Detection, DetectionContext, Detector } from "./types.js";

export interface ScannerSignatureOptions {
  /** Extra user-agent patterns to treat as scanners. */
  extraPatterns?: RegExp[];
  score?: number;
  /** Also flag requests that send no User-Agent at all. Default true. */
  flagMissingUserAgent?: boolean;
  respondWith?: string;
}

/** User agents belonging to well-known scanning, fuzzing, and exploitation tools. Exported so edge configs (e.g. the nginx generator) can reuse the same list. */
export const scannerUserAgentPatterns: RegExp[] = [
  /sqlmap/i,
  /nikto/i,
  /nmap|masscan|zgrab|zmap/i,
  /dirbuster|dirb|gobuster|feroxbuster|ffuf|wfuzz/i,
  /nuclei|acunetix|nessus|openvas|qualys|arachni|w3af/i,
  /metasploit|hydra|havij|nette tester/i,
  /burpsuite|burp collaborator/i,
  /python-requests|go-http-client|libwww-perl|curl\/|wget\//i,
];

/**
 * Flags requests whose User-Agent identifies a security scanner or a bare
 * scripting HTTP client. Trivially spoofed, so it scores modestly — its value
 * is catching unsophisticated automation and corroborating other detections.
 */
export function scannerSignatureDetector(options: ScannerSignatureOptions = {}): Detector {
  const patterns = [...scannerUserAgentPatterns, ...(options.extraPatterns ?? [])];
  const score = options.score ?? 6;
  const flagMissing = options.flagMissingUserAgent ?? true;

  return {
    id: "scanner-signature",
    description: "User-Agent matches a known scanner, exploitation tool, or bare scripting client",
    inspect(ctx: DetectionContext): Detection | undefined {
      const raw = ctx.headers["user-agent"];
      const userAgent = Array.isArray(raw) ? raw[0] : raw;

      if (!userAgent) {
        if (!flagMissing) return undefined;
        const detection: Detection = {
          detectorId: "scanner-signature",
          reason: "Request sent no User-Agent header",
          score: Math.max(1, Math.round(score / 2)),
          metadata: { userAgent: null },
        };
        if (options.respondWith) detection.respondWith = options.respondWith;
        return detection;
      }

      const matched = patterns.find((pattern) => pattern.test(userAgent));
      if (!matched) return undefined;

      const detection: Detection = {
        detectorId: "scanner-signature",
        reason: `User-Agent matches known tooling signature: ${userAgent.slice(0, 80)}`,
        score,
        metadata: { userAgent, pattern: matched.source },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}
