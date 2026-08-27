import net from "node:net";

/**
 * A tiny validating reader over a parsed TOML table.
 *
 * Every accessor records which key it consumed, so `done()` can report keys the
 * schema does not know about. A typo in a config file is otherwise silent — it
 * just leaves the default in place — which is the worst possible failure mode
 * for a security tool.
 */

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

type Raw = Record<string, unknown>;

function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  if (value instanceof Date) return "a date";
  if (typeof value === "object") return "a table";
  return `${typeof value} (${JSON.stringify(value)})`;
}

function isTable(value: unknown): value is Raw {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Date);
}

/**
 * Turns a TOML string into a RegExp. A `/pattern/flags` literal keeps its own
 * flags; a bare string is compiled case-insensitively, which is what you want
 * for nearly every path/user-agent pattern in this project.
 */
export function toRegExp(value: string, onError: (message: string) => never): RegExp {
  const literal = /^\/(.*)\/([a-z]*)$/s.exec(value);
  try {
    return literal ? new RegExp(literal[1]!, literal[2]!) : new RegExp(value, "i");
  } catch (err) {
    return onError(`is not a valid regular expression: ${(err as Error).message}`);
  }
}

export class Section {
  readonly path: string;
  readonly source: string;
  private readonly raw: Raw;
  private readonly seen = new Set<string>();

  constructor(source: string, path: string, raw: Raw) {
    this.source = source;
    this.path = path;
    this.raw = raw;
  }

  private keyPath(key?: string): string {
    const parts = [this.path, key].filter((part) => part !== undefined && part !== "");
    return parts.length > 0 ? parts.join(".") : "<root>";
  }

  fail(key: string | undefined, message: string): never {
    throw new ConfigError(`${this.source}: [${this.keyPath(key)}] ${message}`);
  }

  /** True when the key is present in the file (as opposed to falling back to a default). */
  has(key: string): boolean {
    return this.raw[key] !== undefined;
  }

  private take(key: string): unknown {
    this.seen.add(key);
    return this.raw[key];
  }

  /** Raw value, for the few keys that accept more than one TOML shape. */
  value(key: string): unknown {
    return this.take(key);
  }

  string(key: string): string | undefined;
  string(key: string, fallback: string): string;
  string(key: string, fallback?: string): string | undefined {
    const value = this.take(key);
    if (value === undefined) return fallback;
    if (typeof value !== "string") this.fail(key, `must be a string, got ${describe(value)}`);
    return value;
  }

  enum<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
    const value = this.string(key);
    if (value === undefined) return fallback;
    if (!allowed.includes(value as T)) this.fail(key, `must be one of ${allowed.map((a) => `"${a}"`).join(", ")}, got "${value}"`);
    return value as T;
  }

  number(key: string): number | undefined;
  number(key: string, fallback: number): number;
  number(key: string, fallback?: number): number | undefined {
    const value = this.take(key);
    if (value === undefined) return fallback;
    if (typeof value === "bigint") return Number(value);
    if (typeof value !== "number" || !Number.isFinite(value)) this.fail(key, `must be a number, got ${describe(value)}`);
    return value as number;
  }

  /** A number that must be a non-negative integer — ports, thresholds, durations. */
  integer(key: string): number | undefined;
  integer(key: string, fallback: number): number;
  integer(key: string, fallback?: number): number | undefined {
    const value = this.number(key);
    if (value === undefined) return fallback;
    if (!Number.isInteger(value) || value < 0) this.fail(key, `must be a non-negative integer, got ${value}`);
    return value;
  }

  boolean(key: string): boolean | undefined;
  boolean(key: string, fallback: boolean): boolean;
  boolean(key: string, fallback?: boolean): boolean | undefined {
    const value = this.take(key);
    if (value === undefined) return fallback;
    if (typeof value !== "boolean") this.fail(key, `must be true or false, got ${describe(value)}`);
    return value;
  }

  /** Accepts either `1500` or `[1000, 3000]` (a randomized range). */
  numberOrRange(key: string): number | [number, number] | undefined {
    const value = this.take(key);
    if (value === undefined) return undefined;
    if (typeof value === "number") return value;
    if (Array.isArray(value) && value.length === 2 && value.every((entry) => typeof entry === "number")) {
      const [min, max] = value as [number, number];
      if (min > max) this.fail(key, `range minimum (${min}) must not exceed the maximum (${max})`);
      return [min, max];
    }
    this.fail(key, `must be a number or a [min, max] pair, got ${describe(value)}`);
  }

  stringArray(key: string): string[] | undefined;
  stringArray(key: string, fallback: string[]): string[];
  stringArray(key: string, fallback?: string[]): string[] | undefined {
    const value = this.take(key);
    if (value === undefined) return fallback;
    if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
      this.fail(key, `must be an array of strings, got ${describe(value)}`);
    }
    return value as string[];
  }

  integerArray(key: string): number[] | undefined;
  integerArray(key: string, fallback: number[]): number[];
  integerArray(key: string, fallback?: number[]): number[] | undefined {
    const value = this.take(key);
    if (value === undefined) return fallback;
    if (!Array.isArray(value) || value.some((entry) => !Number.isInteger(entry))) {
      this.fail(key, `must be an array of integers, got ${describe(value)}`);
    }
    return value as number[];
  }

  regexp(key: string): RegExp | undefined {
    const value = this.string(key);
    if (value === undefined) return undefined;
    return toRegExp(value, (message) => this.fail(key, message));
  }

  regexpArray(key: string): RegExp[] | undefined {
    const value = this.stringArray(key);
    if (value === undefined) return undefined;
    return value.map((entry) => toRegExp(entry, (message) => this.fail(key, message)));
  }

  /**
   * IPs and CIDR ranges. Validated here because IpAllowlist silently ignores a
   * malformed entry — an operator would see their monitoring range "configured"
   * while it exempts nothing at all.
   */
  ipList(key: string, fallback: string[]): string[] {
    const entries = this.stringArray(key, fallback);
    for (const entry of entries) {
      const slash = entry.indexOf("/");
      const address = slash === -1 ? entry : entry.slice(0, slash);
      const version = net.isIP(address);
      if (version === 0) this.fail(key, `entry "${entry}" is not a valid IP address or CIDR range`);
      if (slash !== -1) {
        const prefix = Number(entry.slice(slash + 1));
        const max = version === 4 ? 32 : 128;
        if (!/^\d+$/.test(entry.slice(slash + 1)) || !Number.isInteger(prefix) || prefix < 0 || prefix > max) {
          this.fail(key, `entry "${entry}" has an invalid /prefix (expected 0-${max} for IPv${version})`);
        }
      }
    }
    return entries;
  }

  /** A table whose values must all be strings — e.g. a set of extra HTTP headers. */
  stringTable(key: string): Record<string, string> | undefined {
    const value = this.take(key);
    if (value === undefined) return undefined;
    if (!isTable(value)) this.fail(key, `must be a table, got ${describe(value)}`);
    for (const [name, entry] of Object.entries(value)) {
      if (typeof entry !== "string") this.fail(`${key}.${name}`, `must be a string, got ${describe(entry)}`);
    }
    return value as Record<string, string>;
  }

  /** A nested table. Returns an empty section when absent, so defaults apply uniformly. */
  section(key: string): Section {
    const value = this.take(key);
    if (value === undefined) return new Section(this.source, this.keyPath(key), {});
    if (!isTable(value)) this.fail(key, `must be a table, got ${describe(value)}`);
    return new Section(this.source, this.keyPath(key), value);
  }

  /** An array of tables — `[[detectors.decoy-path.decoys]]` and friends. */
  sections(key: string): Section[] | undefined {
    const value = this.take(key);
    if (value === undefined) return undefined;
    if (!Array.isArray(value) || value.some((entry) => !isTable(entry))) {
      this.fail(key, `must be an array of tables, got ${describe(value)}`);
    }
    return (value as Raw[]).map((entry, index) => new Section(this.source, `${this.keyPath(key)}[${index}]`, entry));
  }

  /** Names of the keys present in this table, for sections keyed by detector/action id. */
  keys(): string[] {
    return Object.keys(this.raw);
  }

  /** Rejects any key the schema did not read. Call once every section is parsed. */
  done(): void {
    const unknown = Object.keys(this.raw).filter((key) => !this.seen.has(key));
    if (unknown.length > 0) {
      throw new ConfigError(`${this.source}: [${this.keyPath()}] has unknown key${unknown.length > 1 ? "s" : ""}: ${unknown.join(", ")}`);
    }
  }
}
