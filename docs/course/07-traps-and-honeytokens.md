# Lesson 7 — Traps and honeytokens

**Goal:** plant the two kinds of proof you control — a credential nobody legitimate was
given, and markup nobody can reach — and understand what each rests on.

← [Course](index.md) · Prev: [Decoys](06-decoys.md) · Next: [Identity and crawler verification](08-identity.md)

---

## Why these two

Everything in lessons 5 and 6 was suspicion, except a self-declared attack tool. The guard
from [lesson 4](04-the-guard.md) will not let suspicion block anyone in front of Pantry,
so if Pantry is ever to block a persistent attacker it needs proof, and the most reliable
proof is the kind you plant.

| | Honeytoken | Trap |
| --- | --- | --- |
| What you plant | a fake credential somewhere only an attacker reads | a link or form field no person can reach |
| What it proves | the client read the bait and used what it found | the client parsed the markup and followed or filled everything |
| Detector | `honeytoken`, off by default | `trap`, off by default |
| Score | 15 | 15 |

## Honeytokens

`pantry/lesson-07.mjs`:

```js
import { HoneypotEngine, honeytokenDetector } from "@osqd/hackerpot";

const TOKEN = "AKIA_PANTRY_7Q2XK4";

const engine = new HoneypotEngine({
  extraDetectors: [honeytokenDetector({ tokens: [{ value: TOKEN, label: "decoy-env-aws-key" }] })],
});

const tries = {
  bearer: { authorization: `Bearer ${TOKEN}` },
  basic: { authorization: `Basic ${Buffer.from(`deploy:${TOKEN}`).toString("base64")}` },
};

for (const [label, extra] of Object.entries(tries)) {
  const r = await engine.evaluate({
    method: "GET", path: "/api/recipes", query: {},
    headers: { host: "pantry.example", "user-agent": "python-requests/2.32.3", ...extra },
    ip: "203.0.113.80",
  });
  const token = r.detections.find((d) => d.detectorId === "honeytoken");
  console.log(`${label.padEnd(7)} certain=${token.certain} +${token.score} ${token.reason}`);
}
```

### Checkpoint

```
bearer  certain=true +15 Honeytoken "decoy-env-aws-key" replayed in header.authorization
basic   certain=true +15 Honeytoken "decoy-env-aws-key" replayed in header.authorization (basic, decoded)
```

The second line is the one worth noticing. An attacker who found a password tries it as a
Basic credential, where the token never appears literally — only its base64. So
`Authorization` and `Proxy-Authorization` Basic values are decoded before matching.
**Nothing else is decoded**: guessing at base64 inside arbitrary values would produce
false positives, and this detector feeds proof.

The label is how an incident tells you *which* bait leaked. Make every planted value
unique, and shaped like the real thing.

## Traps

A trap is a link or a form field that is in Pantry's HTML but that no sequence of clicks,
keystrokes or screen-reader gestures reaches. Anything that requests or fills one parsed
the markup.

`pantry/lesson-07b.mjs`:

```js
import { HoneypotEngine, renderTrapField, renderTrapLink, trapDetector, trapRobotsEntries } from "@osqd/hackerpot";
import { CHROME } from "./browser.mjs";

const TRAP = "/internal/export.csv";

console.log(renderTrapLink(TRAP));
console.log(renderTrapField("website"));
console.log(trapRobotsEntries([TRAP]));

const engine = new HoneypotEngine({ extraDetectors: [trapDetector({ paths: [TRAP], formFields: ["website"] })] });

const requests = [
  ["trap link", { method: "GET", path: TRAP, query: {} }],
  ["filled field", { method: "GET", path: "/signup", query: { email: "a@b.example", website: "https://seo.example" } }],
  ["empty field", { method: "GET", path: "/signup", query: { email: "a@b.example", website: "" } }],
];
for (const [label, request] of requests) {
  const r = await engine.evaluate({ ...request, headers: CHROME, ip: "198.51.100.90" }, { blockRequiresProof: true });
  const trap = r.detections.find((d) => d.detectorId === "trap");
  console.log(`${label.padEnd(13)} ${trap ? `certain=${trap.certain} +${trap.score} ${trap.reason}` : "nothing fired"}`);
}
```

### Checkpoint

```
<a href="/internal/export.csv" rel="nofollow noindex" aria-hidden="true" tabindex="-1" style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden">Archive index</a>
<div aria-hidden="true" style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden"><label for="website">Leave this field empty</label><input type="text" id="website" name="website" tabindex="-1" autocomplete="off" value=""></div>
User-agent: *
Disallow: /internal/export.csv
trap link     certain=true +15 Requested trap path /internal/export.csv
filled field  certain=true +15 Filled the hidden form field "website"
empty field   nothing fired
```

Notice the request carried a **complete Chrome header set** and was still proven. A trap
does not care what the client claims to be, only where it went.

## What the guarantee rests on

Three things, and all three are Pantry's job, not the library's:

1. **The trap is invisible and unfocusable.** Use `renderTrapLink` and `renderTrapField`,
   which set `aria-hidden`, `tabindex="-1"` and off-screen positioning together. Keyboard
   and screen-reader users are the people most at risk from a careless trap.
2. **Trap paths are disallowed in robots.txt**, so a crawler that obeys it is never caught.
   Without the disallow, Googlebot follows the link, and you have proven something false
   about a crawler you wanted.
3. **A trap path never serves anything real**, now or later. A trap that becomes a real
   endpoint proves things about your own users.

That is why `trap` is off by default: until you have done all three, a request for
`/internal/export.csv` proves nothing.

## The form-field trap needs one more step

The checkpoint put the field in the query string. The forms worth protecting are POSTs, and
their fields arrive in the **body** — which, from [lesson 5](05-detectors.md), is read only
for requests something already flagged. A form bot with a perfect browser disguise flags
nothing on its headers, so its body is never read, and the filled field is never seen.

The fix is `trapFormGuard`, mounted on the form's route after your own body parser. You
will wire it into Pantry's signup in [lesson 10](10-in-front-of-an-app.md). Skip it and the
field is rendered, filled by a bot, and silently ignored.

## Exercise

A honeytoken is only proof if somebody can find it. Plant Pantry's token inside the fake
`.env` the `dotenv` decoy serves, then send two requests from one `curl` client: one
reading `/.env`, and one using the key it found against `/api/recipes`. What does the
second request get?

<details>
<summary>Checkpoint</summary>

```js
import { HoneypotEngine, decoyPathDetector, defaultDecoyPaths, defaultDetectors, honeytokenDetector } from "@osqd/hackerpot";

const TOKEN = "AKIA_PANTRY_7Q2XK4";
const dotenv = defaultDecoyPaths.find((d) => d.id === "dotenv");
const planted = {
  ...dotenv,
  payload: { ...dotenv.payload, body: `APP_ENV=production\nAWS_ACCESS_KEY_ID=${TOKEN}\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n` },
};

const engine = new HoneypotEngine({
  detectors: [
    ...defaultDetectors().map((d) => (d.id === "decoy-path" ? decoyPathDetector([planted, ...defaultDecoyPaths.filter((x) => x.id !== "dotenv")]) : d)),
    honeytokenDetector({ tokens: [{ value: TOKEN, label: "decoy-env-aws-key" }] }),
  ],
});

const ua = { host: "pantry.example", "user-agent": "curl/8.4.0" };
const read = await engine.evaluate({ method: "GET", path: "/.env", query: {}, headers: ua, ip: "203.0.113.81" }, { blockRequiresProof: true });
console.log("1.", read.actionId, "serves:", JSON.stringify(read.detections[0].metadata.payload.body.split("\n")[1]));

const used = await engine.evaluate(
  { method: "GET", path: "/api/recipes", query: {}, headers: { ...ua, "x-api-key": TOKEN }, ip: "203.0.113.81" },
  { blockRequiresProof: true },
);
console.log("2.", `total ${used.totalScore}`, used.actionId, used.detections.map((d) => `${d.detectorId}${d.certain ? " [proof]" : ""}`).join(", "));
```

```
1. decoy-content serves: "AWS_ACCESS_KEY_ID=AKIA_PANTRY_7Q2XK4"
2. total 37 tarpit honeytoken [proof], scanner-signature
```

**A tarpit, not a block** — and that is worth sitting with. The second request carries
proof, so a block is now *allowed*. It is not *chosen*: the default ladder blocks at 40, and
this address is at 37. Proof removes the guard's objection; the policy still decides.

If Pantry wants proof to block at once, that is a policy decision, and you write it in
[lesson 14](14-extending.md).
</details>

## What you learned

- A honeytoken proves the bait was read and used; plant unique, realistic values
- Basic credentials are decoded before matching, and nothing else is
- A trap proves the markup was parsed, and rests on three things only the deployment can do
- A POST form's trap field needs `trapFormGuard`, or it silently catches nothing
- Proof makes a block permissible; the policy decides whether to block

## Where to read more

- [Traps and honeytokens](../detection/traps-and-honeytokens.md) — wiring, TOML, planting well
- [The proof guard](../concepts/the-guard.md#what-counts-as-proof) — the five kinds of proof
- [Adapters](../integration/adapters.md#trap-forms) — `trapFormGuard` beside the other front ends

Next: [Identity and crawler verification](08-identity.md).
