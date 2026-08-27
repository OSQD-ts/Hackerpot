import type { Detection, DetectionContext, Detector } from "./types.js";

export interface SensitiveFileOptions {
  /** Override the default set of risky path/extension patterns. */
  patterns?: RegExp[];
  score?: number;
  respondWith?: string;
}

/**
 * Requests for file types that only an attacker probing for leaks would ask
 * for: editor swap/backup files, source and database dumps, VCS/IDE metadata
 * directories, and archives at the web root. This generalizes the exact
 * decoy-path list to catch enumeration of arbitrary risky filenames
 * (`/wp-config.php.bak`, `/index.php~`, `/db.sql`, `/.svn/entries`, …).
 */
const DEFAULT_PATTERNS: RegExp[] = [
  // Editor / backup / temp copies, including double extensions like ".php.bak"
  /\.(bak|old|orig|save|swp|swo|tmp|temp|copy|back|dist)$/i,
  /\.(php|asp|aspx|jsp|js|ts|py|rb|env|ini|conf|config|yml|yaml|json|xml)~$/i,
  /\.(php|asp|aspx|jsp|py|rb)\.(bak|old|orig|save|txt|dist|sample|swp)$/i,
  // Database and data dumps
  /\.(sql|sqlite|sqlite3|db|mdb|dump)$/i,
  // Archives at a web path (often leaked backups)
  /\/[^/]+\.(zip|tar|tar\.gz|tgz|rar|7z|gz|bz2)$/i,
  // Version-control / IDE / OS metadata directories and files
  /\/\.(svn|hg|bzr|cvs)(\/|$)/i,
  /\/\.(idea|vscode)(\/|$)/i,
  /\/(\.DS_Store|Thumbs\.db)$/i,
  // Log files and common sensitive config filenames anywhere in the path
  /\/[^/]*\.(log)$/i,
  /\/(wp-config|configuration|settings|secrets|credentials)\.(php|inc|ini|yml|yaml|json)(\.[a-z0-9]+)?$/i,
];

export function sensitiveFileDetector(options: SensitiveFileOptions = {}): Detector {
  const patterns = options.patterns ?? DEFAULT_PATTERNS;
  const score = options.score ?? 6;

  return {
    id: "sensitive-file",
    description: "Request targeted a risky file type (backup, dump, source, VCS/IDE metadata)",
    inspect(ctx: DetectionContext): Detection | undefined {
      const matched = patterns.find((pattern) => pattern.test(ctx.path));
      if (!matched) return undefined;
      const detection: Detection = {
        detectorId: "sensitive-file",
        reason: `Request for a risky file type: ${ctx.path}`,
        score,
        metadata: { path: ctx.path, pattern: matched.source },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}

export const sensitiveFilePatterns = DEFAULT_PATTERNS;
