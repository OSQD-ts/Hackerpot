# Stores

Where incidents and scores live: memory, a rotating file, Redis, Elasticsearch, and composites.

← [Documentation](../index.md) · [Operations](index.md)

---

The **store** holds incidents and per-address scores. Every store implements the small
`HitStore` interface, so they are interchangeable: swap persistence without touching detection
or response.

```ts
interface HitStore {
  record(hit: HoneypotHit): void | Promise<void>;
  list(): HoneypotHit[] | Promise<HoneypotHit[]>;       // retained hits, oldest first, bounded
  scoreFor(ip: string): number | Promise<number>;
  query?(query: HitQuery): HoneypotHit[] | Promise<HoneypotHit[]>;
}
```

| Store | Use it for |
| --- | --- |
| `MemoryStore` | the default: fast, in-process, lost on restart |
| `FileStore` | a single instance that must survive restarts: an append-only JSONL log with rotation |
| `RedisStore` | several replicas: shared scores and hit log, with optional score decay |
| `ElasticStore` | long-term searchable retention in Elasticsearch or OpenSearch |
| `CompositeStore` | several at once: a fast primary for scoring plus a durable log |

```ts
import { CompositeStore, ElasticStore, FileStore, MemoryStore, RedisStore } from "@osqd/hackerpot";

new MemoryStore({ maxHits: 10_000 });
new FileStore({ path: "./data/hits.jsonl", loadOnStart: true });
new RedisStore({ redisOptions: { host: "127.0.0.1", port: 6379 }, keyPrefix: "hackerpot:", scoreTtlSeconds: 3600, maxHits: 1500 });
new ElasticStore({ node: "http://localhost:9200", index: "hackerpot-hits", apiKey: "…", onError: console.error });
new CompositeStore(redisStore, fileStore);     // reads from the first, writes to all
```

In the standalone service, a store is enabled by setting its location: `[store.file] path`,
`[store.redis] url`, `[store.elastic] node`. With none, `MemoryStore` is used. With several, they
are composed.

## A store never takes the honeypot down

`scoreFor` is on the request path: the engine reads an address's score for every flagged request.
The engine wraps it, so a broken store degrades to a score of 0 rather than failing the request, and
wraps `record` so a failed write is reported through `onError` (`kind: "store-error"` in the
service log) rather than raised.

That degradation only works if a failing read actually **fails**. A promise that never settles never
reaches the handler. So the network stores have deadlines: `RedisStore` rejects after
`max_retries_per_request` and `command_timeout_ms`, and `ElasticStore` after `timeout_ms`.
ioredis's "retry forever" mode would otherwise hang every request, grow its offline queue at the
attacker's rate, and in middleware mode hang the host application too. A dead logging backend should
cost you the log, not the service.

A store that fails silently looks exactly like a healthy one from outside. After changing store
settings, watch the log for `store-error`.

## `MemoryStore`

A bounded ring buffer: only the most recent `maxHits` incidents are kept, so a flood of distinct
requests cannot grow memory without limit. Per-address scores are kept separately and survive the
incidents that produced them, so blocking still works on hits that have aged out.

| Option | TOML `[store.memory]` | Default |
| --- | --- | --- |
| `maxHits` | `max_hits` | `10000` |
| `maxScoreEntries` | `max_score_entries` | `100000`, least recently updated shed first |

With no durable store, the management API, the dashboard and the IOC feed all read from here, so
`max_hits` is also how far back they can see. The config refuses `0` for either: `max_hits = 0`
looks like a retention setting and is an off switch for every read path.

## `FileStore`

Append-only JSONL, zero dependencies. Scores are rebuilt from the file on startup.

| Option | TOML `[store.file]` | Default |
| --- | --- | --- |
| `path` | `path` | required; setting it enables the store |
| `loadOnStart` | `load_on_start` | `true`: replay the file so scores survive a restart |
| `maxBytes` | `max_bytes` | `134217728` (128 MB): roll point; `0` disables rotation |
| `maxArchives` | `max_archives` | `10`; `0` keeps every archive |
| `maxArchiveAgeMs` | `max_archive_age_seconds` | `0` (off) |
| `compressArchives` | `compress_archives` | `true` |
| `maxScoreEntries` | `max_score_entries` | `100000` |
| `maxReadBytes` | — | `67108864` (64 MB): the most one read pulls from the tail of the file |
| `onError` | — | |

**Writes are batched and asynchronous**, so the request path never blocks on the disk, and
`record()` resolves only once the line is durable, so read-after-write still holds. A synchronous
append would freeze every in-flight request for each disk write, at a frequency the attacker chose.

**Reads stream.** The file's size is a remote input: one record per malicious request, headers and up
to 64 KB of body included. Loading it whole was a remote out-of-memory on two paths, the management
reads and the startup replay, and the second meant a process that could not start again until
someone truncated the file. Both now stream a chunk at a time. A corrupt line is skipped rather than
turning every endpoint into a permanent 500.

### Rotation and retention

Left unrotated, the attacker decides how fast the file fills the volume, which takes down more than
the honeypot. So the live file rolls into a timestamped, gzipped archive at `max_bytes`, and archives
are pruned by count and age:

```
/data/hits.jsonl                                  # live segment, always < max_bytes
/data/hits-2026-08-29T11-28-22-411Z.jsonl.gz      # archives, newest first
/data/hits-2026-08-29T11-28-22-338Z.jsonl.gz
/data/hits.jsonl.scores.json                      # score checkpoint
```

Reads (`/incidents`, `/stats`, `/ioc`, `/sessions`, `/actors`) come from the live segment, so they
are bounded by `max_bytes`. Archives are for your own pipeline:

```bash
zcat /data/hits-*.jsonl.gz | jq -r 'select(.score >= 10) | .ip' | sort -u
```

**Scores survive rotation.** Rotation empties the live segment and `load_on_start` replays it, so on
its own the first roll would silently reset every attacker's accrued score on the next restart, and
cumulative score is what crosses `block_threshold`. A small checkpoint (`<path>.scores.json`) is
written at each roll, at the one moment the live segment is empty, so checkpoint plus live segment is
the complete history with nothing counted twice. An address's score is kept even after the archives
holding its records are pruned.

Set `max_bytes = 0` only when something else rotates the file (logrotate, a sidecar). The config
refuses `max_bytes = 0` with `max_archives > 0`, since nothing would ever create or prune an archive.

`RotatingJsonlWriter` and `ScoreLedger` are exported, if you want the same guarantees for a log of
your own.

## `RedisStore`

Shares scores and the hit log across every instance pointing at one Redis: essential behind a load
balancer, where an attacker's requests land on different replicas.

| Option | TOML `[store.redis]` | Default |
| --- | --- | --- |
| `client` or `redisOptions` | `url` | required; setting `url` enables it |
| `keyPrefix` | `key_prefix` | `"hackerpot:"` |
| `scoreTtlSeconds` | `score_ttl_seconds` | none (`0` in TOML): scores never expire |
| `maxHits` | `max_hits` | `10000` |
| — | `max_retries_per_request` | `3`; `0` waits forever, and hangs requests during an outage |
| — | `command_timeout_ms` | `5000`; `0` disables |

**Why a score TTL matters.** Without one, an address's suspicion only grows. A TTL on the score key,
refreshed on each hit, lets a quiet address decay, so a shared address that tripped something once
does not stay near the block threshold forever.

**`max_hits` is Redis's memory ceiling.** The hit log is one list holding whole incidents, bodies
included, so its worst case is `max_hits × 64 KB`: 10,000 is roughly 630 MB. Size it against the
memory Redis actually has. A `maxmemory-policy` does not help: the log is a single key, so LRU
eviction discards the small score and block keys (the state blocking depends on) before it touches
the list that is growing. An attacker who fills it gets Redis OOM-killed and restarted empty, which
resets every score and every block. The compose file sets `REDIS_MAX_HITS=1500` to fit its 256 MB
container; raise both together.

A plain `limit` read slices the list server-side; a filtered read fetches and matches locally,
because trimming before filtering would answer from the newest N records rather than the newest N
matches.

## `ElasticStore`

Hits become documents you can dashboard in Kibana or OpenSearch Dashboards and retain far longer
than any other store. Dependency-free: it talks to the REST API over `fetch`.

| Option | TOML `[store.elastic]` | Default |
| --- | --- | --- |
| `node` | `node` | required; http(s); setting it enables the store |
| `index` | `index` | `"hackerpot-hits"` |
| `apiKey` | `api_key` | sent as `ApiKey …` |
| `username`, `password` | `username`, `password` | Basic; both or neither, and setting one is a startup error |
| `maxHits` | `max_hits` | `1000`: documents a read returns |
| `refresh` | `refresh` | `false`; `true` makes each write immediately searchable (slower; for tests) |
| `timeoutMs` | `timeout_ms` | `10000`; `scoreFor` is on the request path |
| `onError`, `fetch` | — | |

Scores are a `sum` aggregation over an address's documents, with no decay. **`record()` never
throws**: a cluster that is down cannot take the honeypot offline, and failures go to `onError`.
Pair it in a `CompositeStore` with a `RedisStore` for fast shared scoring *and* searchable retention.

## `CompositeStore`

`new CompositeStore(primary, ...others)` writes every hit to all of them and reads (`list`,
`scoreFor`, `query`) from the primary. The usual shape is a fast primary for scoring and a durable
audit log beside it. The service composes automatically when more than one store is enabled.

## Reading a store

`list()` returns the retained hits **oldest first**, on every backend, bounded by that backend's
retention. `ElasticStore` queries newest-first (with `size`, that is what selects the newest
documents) and reverses before returning, so a caller never needs to know which store is behind it.

`query(q)` is an optional bounded, filtered read with the same ordering:

```ts
interface HitQuery {
  ip?: string;          // only this source address
  detector?: string;    // only hits where this detector fired
  fingerprint?: string; // only this actor fingerprint
  sinceMs?: number;     // at or after this epoch-ms time
  limit?: number;       // at most this many: the MOST RECENT ones
}
```

All five stores implement it, each pushing down what its backend can: Elasticsearch turns `ip` and
`sinceMs` into a real query, Redis slices for a plain `limit`, the file store streams into a bounded
window, and the memory store walks back from the newest hit and stops at `limit`.

**A custom store can omit `query()`.** Callers fall back to `list()` with identical filtering
(`queryHits`, `applyQuery`, `matchesQuery`, `takeLatest` are exported), so it is a performance
interface, never a correctness one. The aggregate endpoints read `list()` by design.

## A store of your own

```ts
import type { HitStore, HoneypotHit } from "@osqd/hackerpot";

class PostgresStore implements HitStore {
  async record(hit: HoneypotHit) { await db.query("insert into hits (id, ip, doc, score) values ($1, $2, $3, $4)", [hit.id, hit.ip, hit, hit.score]); }
  async list() { return (await db.query("select doc from (select doc, ts from hits order by ts desc limit 10000) t order by ts")).rows.map((r) => r.doc); }
  async scoreFor(ip: string) { return Number((await db.query("select coalesce(sum(score), 0) as s from hits where ip = $1", [ip])).rows[0].s); }
}
```

Keep `scoreFor` fast and give it a deadline: it runs on every flagged request. Keep `list()`
bounded: the aggregate endpoints read all of it.

## What a restart needs

Changing any `[store.*]` section needs a restart: swapping the store would discard accrued scores.
The same is true of `[blocklist]`. See [runtime changes](runtime-changes.md).

## Related

- [Management API](management-api.md) — what reads the store
- [Scores and escalation](../concepts/scoring.md) — what `scoreFor` feeds
- [Docker](../integration/docker.md) — the compose stack's Redis and volume
