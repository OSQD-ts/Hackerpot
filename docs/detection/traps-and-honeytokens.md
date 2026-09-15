# Traps and honeytokens

Hidden links and form fields, and seeded credentials: the two kinds of proof you plant yourself.

← [Documentation](../index.md) · [Detection](index.md)

---

Most detections are suspicion. The [proof guard](../concepts/the-guard.md) will not let
suspicion block anyone in front of a real application, so a middleware deployment that
wants to block needs something that is **proof by construction**. These are the two you
can plant.

| | Trap | Honeytoken |
| --- | --- | --- |
| What you plant | a link or form field no person can reach | a fake credential in a decoy |
| What it proves | the client parsed your markup and followed or filled everything | the client read the bait and used what it found |
| Detector | `trap` (opt-in) | `honeytoken` (opt-in) |
| Default score | 15 | 15 |

## Hidden traps

A trap is a link or a form field that is in your HTML but that no sequence of clicks,
keystrokes or screen-reader gestures reaches. Anything that requests or fills one parsed the
markup, so `trapDetector` marks it `certain`.

The guarantee rests on three things, and all three are the deployment's job:

1. **The trap is invisible and unfocusable.** Use `renderTrapLink` and `renderTrapField`,
   which set `aria-hidden`, `tabindex="-1"` and off-screen positioning together. Keyboard and
   screen-reader users are the people most at risk from a careless trap.
2. **Trap paths are disallowed in robots.txt**, so a crawler that obeys it is never caught.
3. **A trap path never serves anything real**, now or later.

That is why `trap` is off by default: until you have done those three things, a request for
`/internal/export.csv` proves nothing.

### Wiring it up

```ts
import express from "express";
import {
  HoneypotEngine, createMiddleware, generateRobotsTxt,
  renderTrapField, renderTrapLink, trapDetector, trapFormGuard,
} from "@osqd/hackerpot";

const TRAP_PATH = "/internal/export.csv";

const engine = new HoneypotEngine({
  extraDetectors: [trapDetector({ paths: [TRAP_PATH], formFields: ["website"] })],
});

const app = express();
app.use(createMiddleware(engine));
app.get("/robots.txt", (_req, res) => res.type("text/plain").send(generateRobotsTxt({ trapPaths: [TRAP_PATH] })));

// In your page template, once near the end of <body>, and inside the signup form:
const link = renderTrapLink(TRAP_PATH);   // <a href="/internal/export.csv" rel="nofollow noindex" aria-hidden="true" tabindex="-1" style="…">
const field = renderTrapField("website"); // a hidden, labelled, unfocusable input that must arrive empty

// A POST form's fields arrive in the body, which the middleware reads only for requests it
// already flagged. Check them after your body parser:
app.post("/signup", express.urlencoded({ extended: false }), trapFormGuard(engine), signup);
```

In TOML:

```toml
[detectors.trap]
enabled = true
paths = ["/internal/export.csv"]      # must begin with "/"; an entry ending in "/" is a prefix
form_fields = ["website"]
# header_name = "x-trap"
```

`hackerpot robots` adds the trap paths when the section is enabled.

### What fires

| Trap | Fires when |
| --- | --- |
| a path | the normalised path equals an entry, or starts with an entry that ends in `/` |
| a form field | the field arrives as a **non-empty string** in the query, a form-encoded or JSON body, or `formFields` set by `trapFormGuard` |
| a header | the named header is present at all |

Only strings count for a field: this feeds proof, and `String(someObject)` is evidence of
nothing.

### `trapFormGuard`

The middleware sits in front of your routes and reads a body only for requests something
already flagged. A hidden field in a POST form, which is where trap fields go, is therefore
never seen there. `trapFormGuard(engine)` runs **after** your body parser, on the parsed
`req.body`:

- it evaluates the request again with the parsed fields, without counting it a second time
  in the activity window or the audit;
- if `trap` fired, the honeypot answers the request, as the middleware would have;
- otherwise the request continues to your handler;
- it fails open, and honours the allowlist and service tokens.

It takes `blockRequiresProof` and `unprovenBlockFallback`, like the middleware. Give trap
fields names a form filler wants to complete: `website`, `email_confirm`, `company_url`.

`trapRobotsEntries(paths)` returns just the robots.txt lines, if you assemble the file
yourself.

## Honeytokens

A honeytoken is a fake secret you plant somewhere only an attacker would read it: an AWS key
in a decoy `.env`, a password in a fake config, an API key in a JSON response. No legitimate
client has ever been given it, so a request carrying it is the highest-confidence breach
signal there is.

```ts
import { HoneypotEngine, honeytokenDetector } from "@osqd/hackerpot";

new HoneypotEngine({
  extraDetectors: [
    honeytokenDetector({
      tokens: [
        "AKIA_HACKERPOT_HONEYTOKEN_DEMO",
        { value: "sk_live_honeypot_4f7a9c", label: "decoy-billing-config" },
      ],
    }),
  ],
});
```

```toml
[detectors.honeytoken]
tokens = ["AKIA_HACKERPOT_HONEYTOKEN_DEMO"]

# or labelled, so the incident says where it leaked from:
[[detectors.honeytoken.tokens]]
value = "AKIAIOSFODNN7EXAMPLE"
label = "decoy-env-aws-key"
```

Listing any token enables the detector. `HONEYTOKENS=a,b` in the environment replaces the
list.

### Where it looks

Substring matches, in order: the normalised path, the path as sent, every query value, every
header, and the body. It needs the body, so it takes part in the second pass.

**HTTP Basic credentials are decoded.** An attacker who found a password in your fake config
and tries it against a login sends `Authorization: Basic <base64 of user:password>`, where
the token never appears literally. So `Authorization` and `Proxy-Authorization` Basic values
are base64-decoded before matching. **Nothing else is decoded**: guessing at base64 inside
arbitrary values would produce false positives, and this detector feeds proof.

The detection records the label and where it was found:

```json
{ "detectorId": "honeytoken", "reason": "Honeytoken \"decoy-env-aws-key\" replayed in header.authorization (basic, decoded)", "score": 15, "certain": true }
```

### Planting well

- **Make it look real, and unique.** A value shaped like the real thing (`AKIA…`,
  `sk_live_…`), different for every place you plant it, so the label tells you which decoy
  leaked.
- **Plant it where it is served.** A decoy's `payload.body`, a
  [`fake-success`](../responses/actions.md#fake-success) body, a comment in a fake admin page.
- **Never plant a real credential**, and never one that looks like a colleague's.
- Values must match exactly; there is no fuzzy matching.

## Related

- [The proof guard](../concepts/the-guard.md) — what these two make possible
- [Decoys](decoys.md) — where honeytokens usually live
- [Adapters](../integration/adapters.md) — `trapFormGuard` beside the other front ends
