import { statelessPattern } from "../internal/pattern.js";
import type { Detection, DetectionContext, Detector } from "./types.js";

export interface WebShellOptions {
  /** Override the built-in web-shell filename / upload-path patterns. */
  patterns?: RegExp[];
  score?: number;
  respondWith?: string;
}

const DEFAULT_PATTERNS: RegExp[] = [
  // Notorious web-shell filenames dropped after a compromise.
  /\/(c99|c100|r57|wso|b374k|alfa|indoxploit|mini|priv8|shell|cmd|backdoor|webshell|adminer|filesman|marijuana|0byt3m1n1)\w*\.(php\d?|phtml|asp|aspx|jsp|jspx)$/i,
  // Any script executed from an upload/temp/media directory — where scripts should never live.
  /\/(uploads?|files?|media|images?|img|tmp|temp|cache|attachments?|assets|static|public|wp-content\/uploads)\/[^?]*\.(php\d?|phtml|phar|asp|aspx|jsp|jspx|cgi|pl|py|sh)(\?|$)/i,
  // Generic "?cmd=" / "?c=" execution parameter on a PHP-ish endpoint (shells expose these).
  /\.(php\d?|phtml|asp|aspx|jsp)\?.*\b(cmd|command|exec|c|shell|passthru|system|download|dir|act|action)=/i,
];

/**
 * Web-shell activity: a request for a known web-shell filename, an executable
 * script served from an upload/temp directory (where a dropped shell would live),
 * or a script URL carrying a command-execution parameter. This is post-exploitation
 * behavior — someone trying to reach or use a backdoor — so it scores high.
 */
export function webShellDetector(options: WebShellOptions = {}): Detector {
  const patterns = (options.patterns ?? DEFAULT_PATTERNS).map((pattern) => statelessPattern(pattern));
  const score = options.score ?? 9;

  return {
    id: "web-shell",
    description: "Request targets a web-shell filename, an upload-dir script, or a command-exec parameter",
    inspect(ctx: DetectionContext): Detection | undefined {
      // Match against path plus its query, since the exec-parameter pattern needs both.
      const query = Object.entries(ctx.query).map(([k, v]) => `${k}=${v}`).join("&");
      const target = query ? `${ctx.path}?${query}` : ctx.path;
      const matched = patterns.find((pattern) => pattern.test(target));
      if (!matched) return undefined;
      const detection: Detection = {
        detectorId: "web-shell",
        reason: `Web-shell probe: ${ctx.path}`,
        score,
        metadata: { path: ctx.path, pattern: matched.source },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}

export const webShellPatterns = DEFAULT_PATTERNS;
