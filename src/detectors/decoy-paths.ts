import type { Detection, DetectionContext, Detector } from "./types.js";

export interface DecoyPath {
  id: string;
  description: string;
  /** Exact path (trailing slash insensitive) or RegExp tested against the request path. */
  path: string | RegExp;
  method?: string;
  score: number;
  /** Response action id to run when this decoy is hit. */
  respondWith?: string;
  /** Payload handed to the response action — e.g. the fake file body to serve. */
  payload?: { status?: number; contentType?: string; body?: string; location?: string };
}

const FAKE_ENV = [
  "APP_ENV=production",
  "APP_KEY=base64:8fN2q7mR4tYcW1zL9vX3jH6pD0sA5uQe2iB7wG4kM1o=",
  "DB_HOST=127.0.0.1",
  "DB_DATABASE=prod",
  "DB_USERNAME=root",
  "DB_PASSWORD=9xK2!vQ7pL",
  "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
  "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "",
].join("\n");

const FAKE_LOGIN_HTML =
  "<!doctype html><html><head><title>Admin Login</title></head>" +
  "<body><h2>Administrator Login</h2>" +
  '<form method="post"><input name="username" placeholder="Username">' +
  '<input name="password" type="password" placeholder="Password">' +
  '<button type="submit">Log in</button></form></body></html>';

/**
 * Paths that scanners and opportunistic attackers probe for: secrets files,
 * admin/CMS panels, framework debug endpoints, and known RCE probe targets.
 * Nothing here replaces real access control — it is bait that reveals
 * automated recon before it reaches anything real.
 */
export const defaultDecoyPaths: DecoyPath[] = [
  { id: "dotenv", description: "Exposed .env file probe", path: "/.env", score: 10, respondWith: "decoy-content", payload: { status: 200, contentType: "text/plain; charset=utf-8", body: FAKE_ENV } },
  { id: "git-config", description: "Exposed .git directory probe", path: "/.git/config", score: 10, respondWith: "decoy-content", payload: { status: 200, contentType: "text/plain; charset=utf-8", body: '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = https://github.com/example/example.git\n' } },
  { id: "git-head", description: "Exposed .git HEAD probe", path: "/.git/HEAD", score: 8, respondWith: "decoy-content", payload: { status: 200, contentType: "text/plain; charset=utf-8", body: "ref: refs/heads/main\n" } },
  { id: "aws-credentials", description: "AWS credentials file probe", path: "/.aws/credentials", score: 10, respondWith: "decoy-content", payload: { status: 200, contentType: "text/plain; charset=utf-8", body: "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" } },
  { id: "ssh-key", description: "SSH private key probe", path: "/.ssh/id_rsa", score: 10, respondWith: "not-found" },
  { id: "docker-config", description: "Docker registry credentials probe", path: "/.docker/config.json", score: 8, respondWith: "not-found" },

  { id: "wp-login", description: "WordPress login probe", path: "/wp-login.php", score: 5, respondWith: "decoy-content", payload: { status: 200, contentType: "text/html; charset=utf-8", body: FAKE_LOGIN_HTML } },
  { id: "wp-admin", description: "WordPress admin probe", path: /^\/wp-admin(\/.*)?$/, score: 5, respondWith: "redirect", payload: { status: 302, location: "/wp-login.php" } },
  { id: "xmlrpc", description: "WordPress XML-RPC probe (brute-force/amplification target)", path: "/xmlrpc.php", score: 6, respondWith: "decoy-content", payload: { status: 405, contentType: "text/plain; charset=utf-8", body: "XML-RPC server accepts POST requests only." } },
  { id: "phpmyadmin", description: "phpMyAdmin panel probe", path: /^\/phpmyadmin(\/.*)?$/i, score: 6, respondWith: "decoy-content", payload: { status: 200, contentType: "text/html; charset=utf-8", body: FAKE_LOGIN_HTML } },
  { id: "admin-panel", description: "Generic admin panel probe", path: /^\/(admin|administrator)(\/login)?$/i, score: 4, respondWith: "decoy-content", payload: { status: 200, contentType: "text/html; charset=utf-8", body: FAKE_LOGIN_HTML } },

  { id: "spring-actuator-env", description: "Spring Boot Actuator env dump probe", path: "/actuator/env", score: 8, respondWith: "decoy-content", payload: { status: 200, contentType: "application/json", body: JSON.stringify({ profiles: ["default"] }) } },
  { id: "spring-actuator-health", description: "Spring Boot Actuator probe", path: "/actuator/health", score: 3, respondWith: "decoy-content", payload: { status: 200, contentType: "application/json", body: JSON.stringify({ status: "UP" }) } },
  { id: "server-status", description: "Apache mod_status probe", path: "/server-status", score: 5, respondWith: "decoy-content", payload: { status: 403, contentType: "text/plain; charset=utf-8", body: "Forbidden" } },
  { id: "go-pprof", description: "Go net/http/pprof debug endpoint probe", path: /^\/debug\/pprof(\/.*)?$/, score: 7, respondWith: "not-found" },
  { id: "laravel-telescope", description: "Laravel Telescope debug dashboard probe", path: /^\/telescope(\/.*)?$/, score: 6, respondWith: "not-found" },
  { id: "laravel-ignition-rce", description: "Laravel Ignition file-execution RCE probe (CVE-2021-3129)", path: "/_ignition/execute-solution", score: 10, respondWith: "not-found" },
  { id: "phpunit-eval-rce", description: "PHPUnit eval-stdin.php RCE probe", path: "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", score: 10, respondWith: "not-found" },

  { id: "swagger", description: "Swagger/OpenAPI spec probe", path: /^\/(swagger(-ui)?|api-docs|openapi)(\.json)?$/i, score: 3, respondWith: "not-found" },
  { id: "backup-archive", description: "Backup/dump archive probe", path: /^\/(backup|db|dump)\.(zip|sql|tar\.gz|tgz)$/i, score: 7, respondWith: "not-found" },
  { id: "config-file", description: "Generic config file probe", path: /^\/config\.(json|php|yml|yaml)$/i, score: 5, respondWith: "not-found" },
];

function normalize(path: string): string {
  return path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
}

function matches(decoy: DecoyPath, method: string, path: string): boolean {
  const wanted = decoy.method ?? "*";
  if (wanted !== "*" && wanted.toUpperCase() !== method.toUpperCase()) return false;
  if (typeof decoy.path === "string") return normalize(decoy.path) === normalize(path);
  return decoy.path.test(path);
}

/** Fires when a request hits one of the decoy paths — the highest-confidence signal the honeypot has. */
export function decoyPathDetector(decoys: DecoyPath[] = defaultDecoyPaths): Detector {
  return {
    id: "decoy-path",
    description: "Request targeted a decoy path that no legitimate client would know about",
    inspect(ctx: DetectionContext): Detection | undefined {
      const decoy = decoys.find((candidate) => matches(candidate, ctx.method, ctx.path));
      if (!decoy) return undefined;
      const detection: Detection = {
        detectorId: "decoy-path",
        reason: decoy.description,
        score: decoy.score,
        metadata: { decoyId: decoy.id, payload: decoy.payload },
      };
      if (decoy.respondWith) detection.respondWith = decoy.respondWith;
      return detection;
    },
  };
}
