import { randomBytes, randomInt } from "node:crypto";
import type { ResponseAction, ResponseContext } from "./types.js";

export interface FakeDataOptions {
  /**
   * Seed of first names used to synthesize fake user records. Defaults to a small
   * built-in set. Nothing here is real — the point is plausibility, not identity.
   */
  names?: string[];
  /** Fake internal domain used in emails / hostnames. Default "corp.internal". */
  domain?: string;
  /** How many rows a listing-style decoy (users, dump) returns. Default 8. */
  rows?: number;
}

const DEFAULT_NAMES = [
  "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
  "ivan", "judy", "mallory", "oscar", "peggy", "trent", "victor", "walter",
];
const WORDS = ["falcon", "harbor", "cedar", "quartz", "meadow", "granite", "copper", "willow", "summit", "delta"];

function pick<T>(arr: readonly T[]): T {
  return arr[randomInt(arr.length)]!;
}

/** A believable-looking but entirely synthetic password/token. */
function fakeSecret(): string {
  return `${pick(WORDS)}-${pick(WORDS)}-${randomInt(1000, 9999)}`;
}

function hex(bytes: number): string {
  return randomBytes(bytes).toString("hex");
}

/** A fake .env file — the single most-probed decoy target. */
function fakeEnv(domain: string): string {
  return [
    "NODE_ENV=production",
    `APP_URL=https://app.${domain}`,
    `DATABASE_URL=postgres://app:${fakeSecret()}@db.${domain}:5432/app_prod`,
    `REDIS_URL=redis://cache.${domain}:6379/0`,
    `JWT_SECRET=${hex(32)}`,
    `SESSION_SECRET=${hex(24)}`,
    `AWS_ACCESS_KEY_ID=AKIA${randomBytes(8).toString("hex").toUpperCase().slice(0, 16)}`,
    `AWS_SECRET_ACCESS_KEY=${randomBytes(30).toString("base64").replace(/[+/=]/g, "").slice(0, 40)}`,
    `SMTP_HOST=smtp.${domain}`,
    `SMTP_USER=noreply@${domain}`,
    `SMTP_PASSWORD=${fakeSecret()}`,
    `STRIPE_SECRET_KEY=sk_live_${hex(12)}`,
  ].join("\n") + "\n";
}

/** A fake user table as JSON — bait for "I found the /api/users dump" moments. */
function fakeUsers(names: string[], domain: string, rows: number): string {
  const users = Array.from({ length: rows }, (_, i) => {
    const name = names.length ? pick(names) : pick(DEFAULT_NAMES);
    return {
      id: i + 1,
      username: `${name}${randomInt(1, 99)}`,
      email: `${name}@${domain}`,
      role: pick(["user", "user", "user", "editor", "admin"]),
      // A bcrypt-shaped hash of nothing — looks crackable, isn't anything.
      password_hash: `$2b$12$${randomBytes(16).toString("base64").replace(/[+/=]/g, "").slice(0, 22)}${randomBytes(20).toString("base64").replace(/[+/=]/g, "").slice(0, 31)}`,
      last_login: new Date(Date.now() - randomInt(0, 30) * 86400000).toISOString(),
    };
  });
  return JSON.stringify({ users, total: users.length }, null, 2);
}

/** Fake AWS credentials file, matching what an attacker greps ~/.aws/credentials for. */
function fakeAwsCredentials(): string {
  return [
    "[default]",
    `aws_access_key_id = AKIA${randomBytes(8).toString("hex").toUpperCase().slice(0, 16)}`,
    `aws_secret_access_key = ${randomBytes(30).toString("base64").replace(/[+/=]/g, "").slice(0, 40)}`,
    "region = us-east-1",
  ].join("\n") + "\n";
}

/** A fake config dump keyed off the request — generic JSON secrets. */
function fakeConfig(domain: string): string {
  return JSON.stringify(
    {
      environment: "production",
      database: { host: `db.${domain}`, user: "app", password: fakeSecret(), name: "app_prod" },
      cache: { host: `cache.${domain}`, port: 6379 },
      secrets: { jwt: hex(32), encryption_key: hex(32) },
      api_keys: { stripe: `sk_live_${hex(12)}`, sendgrid: `SG.${hex(11)}.${hex(16)}` },
    },
    null,
    2,
  );
}

interface Shape {
  contentType: string;
  render(opts: Required<FakeDataOptions>): string;
}

// Ordered most-specific first; the request path/detector picks the shape.
function shapeFor(ctx: ResponseContext): Shape {
  const path = ctx.path.toLowerCase();
  if (/\.env(\.|$|\?)|\/\.env/.test(path)) {
    return { contentType: "text/plain; charset=utf-8", render: (o) => fakeEnv(o.domain) };
  }
  if (/aws|credentials/.test(path)) {
    return { contentType: "text/plain; charset=utf-8", render: () => fakeAwsCredentials() };
  }
  if (/user|account|member|dump/.test(path)) {
    return { contentType: "application/json", render: (o) => fakeUsers(o.names, o.domain, o.rows) };
  }
  // Default: a generic config/secrets blob.
  return { contentType: "application/json", render: (o) => fakeConfig(o.domain) };
}

/**
 * Serves **freshly-synthesized** fake sensitive data tailored to what the attacker
 * asked for — a fake `.env`, an AWS credentials file, a user table with bcrypt-shaped
 * hashes, or a generic secrets blob. Unlike a static decoy, every hit produces
 * different plausible values, so an attacker can't fingerprint the honeypot by
 * diffing two responses, and any credential they exfiltrate is pure noise that
 * wastes their time when they try to use it. Nothing here maps to anything real.
 */
export function fakeDataAction(options: FakeDataOptions = {}): ResponseAction {
  const resolved: Required<FakeDataOptions> = {
    names: options.names ?? DEFAULT_NAMES,
    domain: options.domain ?? "corp.internal",
    rows: options.rows ?? 8,
  };
  return {
    id: "fake-data",
    description: "Serve freshly-generated fake secrets/credentials tailored to the request",
    execute(ctx: ResponseContext): void {
      const shape = shapeFor(ctx);
      ctx.res.statusCode = 200;
      ctx.res.setHeader("Content-Type", shape.contentType);
      ctx.res.end(shape.render(resolved));
    },
  };
}
