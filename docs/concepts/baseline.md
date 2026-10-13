# The site profile

What your application already knows, fed back to the honeypot.

← [Documentation](../index.md)

---

Every detector except one reasons from the request alone: this path looks like a WordPress
login, that header order is wrong, this address asked for fifteen things in ten seconds. None
of them know what *your* site is. So `/graphql` is a probe on a marketing page and an ordinary
request on an API, and a threshold that is right for one is wrong for the other — which is why
the volume detectors are what operators spend their first week tuning.

Your application already answers that question on every request. A 200 says the path is real;
a 404 says it is not. The **site baseline** is that feedback, collected.

## Feeding it

```ts
engine.reportOutcome({ ip, path, status: res.statusCode });
```

The [middleware](../integration/adapters.md) calls this for every request it passes to your
routes, and for every request the honeypot answers itself (as a miss — a decoy serving
convincing bait says nothing about what your site has). If you dispatch some other way, call
it yourself. It is synchronous, cheap, and safe to call for traffic nothing flagged.

In standalone mode there is no application, so nothing reports outcomes and the baseline stays
empty. That is not a gap: on a listener of its own, every request is unsolicited and novelty
means nothing.

## Three rules

- **It learns only from outcomes, never from requests.** A path is real because your
  application served it, not because somebody asked for it. An attacker cannot teach the
  baseline that `/.env` is a real page by requesting it a thousand times, and the honeypot's
  own 200s never count.
- **It is inert until it knows something.** Until it has seen `min_observations` outcomes
  across `min_served_paths` distinct real paths, `isWarm()` is false and every consumer stands
  down. A cold baseline says "never seen" about your home page, and acting on that would flag
  real visitors every time the process restarts.
- **It is bounded.** Paths are attacker-chosen, so they live in a capped, expiring cache
  (20 000 paths, 24h), and the addresses remembered per unserved path are capped too.

## Reading it

```ts
engine.site?.isServed("/pricing");   // true — the app has served it
engine.site?.noveltyOf("/.env");     // "served" | "missed" | "unseen"
engine.site?.walkers("/admin.php");  // distinct addresses probing a path that doesn't exist
engine.site?.snapshot();             // { paths, servedPaths, observations, missShare }
```

`missShare` is your site's own 404 rate, which is the number every "unusual" judgement should
be measured against rather than guessed at.

Pass `site: null` to `HoneypotEngine` to switch it off, or your own `SiteProfile` to share one
between engines. A custom detector reads it as `ctx.site`.

The class is `SiteProfile`, the option and the property `site`, the names bothandlerjs uses for its
own profile of a site's traffic. The two are not the same class: this one learns from what the
application **served**, bothandlerjs's from what clients **asked for**, because a honeypot sees
the answers and a bot handler sees the questions. Before the names matched they were
`SiteBaseline`, `baseline` and `ctx.baseline`, and those still work, deprecated, for a release.

## What reads it

[`path-novelty`](../detection/detectors.md#path-novelty) — off by default, and the reason the
baseline exists. It fires on an address walking paths your site has never served, or on one
never-served path being walked by many addresses at once: a scan spread thin enough that no
per-address threshold sees it.

## Related

- [Detectors](../detection/detectors.md#path-novelty) — the detector and its options
- [Scores and escalation](scoring.md) — how a detection becomes a response
- [Middleware and adapters](../integration/adapters.md) — where outcomes come from
