# Contributing to hackerpot

Thanks for helping. This project has a few hard-won conventions — following them
keeps the honeypot safe to run next to production and keeps the codebase honest.

## Development

```bash
npm install
npm run typecheck   # src + tests + examples (tsconfig.typecheck.json)
npm test            # Vitest
npm run build       # emit dist/ (ESM + CJS + .d.ts), src only
npm run dev         # local honeypot + management API to poke at
```

Node.js ≥ 20. TypeScript is `strict` with `exactOptionalPropertyTypes` and
`noUncheckedIndexedAccess` — expect the compiler to be picky, on purpose.

## The layers

Detection and response are decoupled. A **detector** ([`src/detectors/`](src/detectors/))
recognizes something and returns a scored `Detection`; it does not decide what
happens next. A **response action** ([`src/responses/`](src/responses/)) produces the
reply. A **policy** picks the action from the detections and the IP's cumulative
score. A **store** ([`src/stores/`](src/stores/)) holds incidents and scores. Add to a
layer without touching the others.

## Adding a detector

1. Write `src/detectors/your-thing.ts` — a factory returning a `Detector`. Return
   `undefined` to pass, a `Detection` to flag. Keep options in an interface with
   sensible defaults.
2. Export it from `src/detectors/index.ts` and, if it should be on by default, add
   it to `defaultDetectors()`.
3. Add a detection test **and** add legitimate cases to
   [`tests/false-positives.test.ts`](tests/false-positives.test.ts) (see below).
4. Wire the config surface in `src/config/*` and `hackerpot.toml` (see below).

**Never throw out of `inspect()`.** The engine awaits every detector in sequence, so
a throw takes down evaluation for that whole request rather than skipping one
detector. If you parse (JSON, base64, a URL), wrap it in `try/catch`. Prefer regex
over parsing where you can, and cap the length of any attacker-controlled value you
scan (16 KB is the convention) so a crafted input can't become a CPU sink.

## The false-positive suite is sacred

Flagging a real user is the worst thing a honeypot can do. Every detector must earn
its place against [`tests/false-positives.test.ts`](tests/false-positives.test.ts) —
a corpus of genuine browser and API-client traffic asserting that **nothing fires**.
If your detector trips a legitimate request, that's a bug in the detector, not the
test: tighten the signature. Add realistic legitimate cases that stress your
detector's boundary.

## The rule: the library owns semantics; config describes and defers

We have hit this three times, each time as a real bug. **The config layer must never
restate something the library owns** — a default list, an IP grammar, a detector
ordering. A restated value goes stale silently the moment the library changes, and
the config file (which wins) then runs the old behavior.

- List-valued defaults (header lists, patterns) live in the library. The TOML file
  *documents* them as commented examples, it does not set them as active keys.
- Validation that depends on library semantics (is this a valid IP/CIDR?) defers to
  the library — e.g. `new IpAllowlist(entries).invalid` is the authoritative check,
  not a parallel validator.
- A drift test asserts `Object.keys(config.detectors)` matches `defaultDetectors()`,
  so adding a detector to the library but not the schema fails loudly.

## Committing

- **Verify the commit, not just your working directory.** A green working tree does
  not prove the commit is green — staging can capture a stale state. Before pushing:

  ```bash
  git archive HEAD | tar -x -C /tmp/verify && ln -s "$PWD/node_modules" /tmp/verify/
  (cd /tmp/verify && npm test && npm run typecheck && npx tsup)
  ```

  CI does exactly this.
- **Green-together beats green-separately-with-a-red-middle.** If a change spans the
  library and the config layer (e.g. a new detector and its schema entry, whose tests
  need each other), land them in one commit. Don't leave an intermediate commit that
  fails its own suite.
- End commit messages with the `Co-Authored-By` trailer if pairing.

## Licensing of contributions

hackerpot is under the [hackerpot Non-Resale License](LICENSE) — free to use and
modify, but not to sell — and the copyright is held by Michał Płatosz rather than by
"the contributors" collectively. That is deliberate: a single holder is what makes it
possible to grant separate commercial terms to someone who asks, and to change the
license later without tracking down every past contributor for consent.

So: by opening a pull request you agree that your contribution is licensed under the
same terms as the project, and that the copyright holder may also license it under
different terms (including commercial ones). If you are not comfortable with that,
say so in the PR before it is merged rather than after.

If you contribute code you did not write — a snippet from a blog post, Stack Overflow,
or another project — say where it came from and under what license. Anything
incompatible with the terms above can't be merged, however good it is.

## Security-sensitive code

Anything that runs on attacker-controlled input (detectors, the SMTP/SSH honeypots,
the firewall enforcer) gets extra scrutiny: no shells, validate IPs before they reach
a command (`net.isIP`), bound resource use (connection and concurrency caps), and
document the trust assumptions (e.g. enforcement acts on the resolved IP, so it needs
`trust_proxy` set correctly). When in doubt, read the code rather than trusting the
description.
