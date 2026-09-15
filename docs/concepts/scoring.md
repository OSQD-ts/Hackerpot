# Scores and escalation

Detection scores, families, cumulative per-IP totals, and the ladder they climb.

← [Documentation](../index.md)

---

## Three numbers

| Number | Where | Means |
| --- | --- | --- |
| a detection's `score` | each `Detection` | how much this one finding is worth |
| a hit's `score` | `HoneypotHit.score` | what this request added: its detections, combined |
| `totalScore` | `HoneypotHit.totalScore` | this address's cumulative score after the request |

Scores are small integers chosen by hand, roughly: 3–5 for a finding with ordinary innocent
explanations (a missing User-Agent, a Swagger probe), 6–8 for a clear probe, 9–10 for an
exploit payload or a credential probe, 15 for something no legitimate client can produce
(a replayed honeytoken, a trap). The default for each detector is on
[the detectors](../detection/detectors.md) page, and every one is configurable.

## Combining one request's detections

A request's score is the sum of its detections, with one exception: **one root cause counts
once.**

A detection may carry a `family`. Within a family only the highest score is added.
An encoded directory traversal is both a traversal payload (`payload-injection`, family
`path-traversal`) and an evasively spelled target (`target-integrity`, family
`path-traversal`), and adding both would score one act as two independent reasons.
Detections with no family each count on their own.

```
/..%2f..%2fetc/passwd   (normalised to /etc/passwd)
  payload-injection   10   family path-traversal   ┐ one family: 10
  target-integrity     7   family path-traversal   ┘
                                                   ───
                                          score     10
```

Without families the same request would have scored 17: one traversal, counted as two reasons.

## Accumulating per address

The engine reads the address's prior total from the store, adds this request's score, and
hands the sum to the policy. The store then records the hit, which is what raises the total
for the next request.

Two consequences worth knowing:

- **Scores only go up**, unless the store says otherwise. `MemoryStore`, `FileStore` and
  `ElasticStore` never decay. `RedisStore` with `scoreTtlSeconds` expires an address's
  score after it goes quiet, so a shared address that tripped something once does not stay
  near the block threshold forever.
- **Scores are shared by everything writing to the store.** The SSH, SMTP, FTP and Telnet
  honeypots record into the same store, so a brute-forcer on SSH raises the same score that
  gets it blocked on HTTP.

Stores cap the number of addresses whose scores they keep (`max_score_entries`, default
100,000), shedding the least recently updated. An address under active attack is never the
one evicted.

## The escalation ladder

The built-in policy, `defaultResponsePolicy(blockThreshold = 40, tarpitThreshold = 15)`:

1. **`totalScore ≥ blockThreshold`** → `block`. A confirmed persistent attacker is blocked
   whatever any single detector asked for.
2. Otherwise, **the top detection's `respondWith`**, if it has one. This is how decoys keep
   serving convincing bait instead of escalating early.
3. Otherwise, **`totalScore ≥ tarpitThreshold`** → `tarpit`.
4. Otherwise → `not-found`.

```toml
[policy]
block_threshold = 40
tarpit_threshold = 15      # must not exceed block_threshold, or nothing is ever tarpitted
```

Because scores accumulate, an attacker climbs the ladder on their own: the first probe gets
a quiet 404 or a convincing fake, a few more draw multi-second tarpits, and once they have
proven persistent they are blocked and cost nothing to serve.

```
probe                          score  total  response
GET /.env                        10     10   decoy-content   (the decoy's respondWith)
GET /wp-login.php                 5     15   decoy-content
GET /phpinfo.php                  5     20   not-found       (respondWith, below the block line)
GET /?id=1' OR '1'='1            10     30   tarpit          (no respondWith, past 15)
GET /.git/config                 10     40   block
```

In middleware mode, step 1 passes through [the proof guard](the-guard.md): without a
`certain` detection the block becomes a tarpit and nothing is blocklisted.

## `respondWith` reads the top detection only

When several detectors fire on one request, the policy reads `detections[0]`, the
highest-scoring one. A lower-scoring detector's `respondWith` is ignored.

This bites the low-scored detectors. `open-redirect` scores 5 and `scanner-signature` scores
6, so a scripted request to an open redirect gets the scanner's outcome, while the same
request from a browser User-Agent honours the open-redirect `respondWith`. If you rely on a
particular detector's routing, raise its `score` above the detectors that co-fire with it,
or put the routing in a [policy of your own](../responses/policy.md), which sees every
detection.

## Choosing thresholds

Lower thresholds block sooner and on less evidence. In standalone mode, where nothing
legitimate should arrive, that is cheap. In middleware mode it is not, which is why the
proof guard exists; but even a tarpit costs a real visitor seconds, so in front of an
application:

- read the [traffic audit](../operations/audit.md)'s `downgrade-spike`: it fires when scores
  reach the block threshold without proof, which is the shape of detectors adding up on
  ordinary traffic;
- [replay a day of your access log](../testing/replay.md) and read which addresses would
  have crossed each line, and why;
- trial a retuned detector in [shadow mode](../detection/shadow-mode.md) before it counts.

## Related

- [The proof guard](the-guard.md) — what stands between a score and a block
- [Writing a policy](../responses/policy.md) — replacing the ladder
- [Response actions](../responses/actions.md) — what each rung does
