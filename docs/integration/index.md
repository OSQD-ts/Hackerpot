# Integration

Where the honeypot sits relative to your application.

← [Documentation](../index.md)

---

Three positions, one engine.

```
                ┌──────────────────────────────── one process ───────────────────────────┐
 1. middleware  │  request ─► honeypot middleware ─► your routes                          │
                └─────────────────────────────────────────────────────────────────────────┘

                ┌──── edge ────┐        ┌──── honeypot ────┐
 2. edge        │  nginx       │─probe─►│  hackerpot serve │
                │              │─rest──►│  your app        │
                └──────────────┘        └──────────────────┘

 3. standalone     its own address or ports; everything that reaches it is unsolicited
```

| Position | What it sees | Reads bodies | Blocks | Page |
| --- | --- | --- | --- | --- |
| **Middleware** | every request your app serves | only for flagged requests | with proof | [Adapters](adapters.md) |
| **Edge** | what nginx diverts | yes | on score | [nginx edge capture](nginx.md) |
| **Standalone** | only unsolicited traffic | always | on score | [Running it standalone](../start/standalone.md) |

They combine. A common shape is the edge diverting statically recognisable probes to a standalone
honeypot, with the middleware in the application catching what the edge cannot see, all writing into
one Redis store so one address has one score.

## Before any of it

| | |
| --- | --- |
| [The client IP](client-ip.md) | Behind a proxy, getting the address right is the highest-consequence setting there is. |
| [Service tokens](service-tokens.md) | Your uptime monitor looks exactly like what the detectors look for. |
| [Docker](docker.md) | The image, the compose stack, and the dashboard profile. |

## Related

- [How it works](../concepts/how-it-works.md) — the lifecycle every position shares
- [The proof guard](../concepts/the-guard.md) — why middleware blocks differently
