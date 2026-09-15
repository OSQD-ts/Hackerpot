# Embedding the dashboard

`<hackerpot-dashboard>` inside a page you already have.

← [Documentation](../index.md) · [Operations](index.md)

---

## The whole integration

```ts
// server
import { createDashboardHandler } from "@osqd/hackerpot";

const dashboard = createDashboardHandler(server.engine, {
  basePath: "/_hackerpot",
  auth: { authorize: (req) => sessionFrom(req)?.role === "admin" },
});
admin.use("/_hackerpot", (req, res) => dashboard(req, res));
```

```html
<!-- your admin page, on the same origin -->
<hackerpot-dashboard src="/_hackerpot"></hackerpot-dashboard>

<script type="module">
  import { defineHackerpotDashboard } from "@osqd/hackerpot/element";
  defineHackerpotDashboard();
</script>
```

The data still comes from a [mounted handler](dashboard.md#mounted-on-a-server-you-already-have), because
there is nowhere else for it to come from. What the element removes is building, routing and styling a
page around it: it fetches `<src>/api/bootstrap` and runs the same client the standalone page runs,
inside your layout, under your heading, in your card.

`@osqd/hackerpot/element` is a separate, browser-only entry point (ESM). Importing the library on your
server pulls none of it.

## Try it

```bash
npm run demo:embedded          # ADMIN_PORT=… to move it off 9675
```

```text
admin panel with an embedded dashboard   http://127.0.0.1:9675/
sign in as demo / hackerpot
120 probes evaluated, so there is something to look at.
```

`demo/embedded.ts` is an "Acme admin" page with the dashboard in its Security section. It evaluates 120
probes from 120 addresses through a real engine before the page opens, mounts the handler at
`/_hackerpot` with basic auth, puts the host page behind the same credential, and serves it under
`default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'`. The password is
`ADMIN_PASSWORD` if set. The whole integration, working, in one file.

---

## What running it in your page costs you

The element renders into a **shadow root** in your document: a separate subtree whose styles do not leak
out and whose internals your page's CSS does not reach by accident. That is what makes it flow with your
layout instead of sitting in a frame. It is worth being exact about what it does not do.

**A shadow root is a styling boundary, not a security boundary.** The element attaches it in `open`
mode, and even a closed one would not stop a script on the page. Any script running in your document can
reach `element.shadowRoot`, read every attacker address and captured request on screen, and call the
dashboard's API with the viewer's credentials. On the standalone page (a different document, which
carries its own CSP) an injected script in your application could do none of that.

**The standalone page refuses to be framed; your page has to refuse for itself.** The dashboard's own
page sends `frame-ancestors 'none'`. The element lives in a document this package does not serve and
cannot set a header on. When it finds a cross-origin ancestor frame it says so in the console, but only
your page can stop it.

So:

- Mount it on a page that is **already behind your admin authentication**.
- Treat an XSS on that page as handing over the dashboard.
- Send `Content-Security-Policy: frame-ancestors 'none'` (or `X-Frame-Options: DENY`) on that page.
- If you would rather have the isolation than the layout, link to the standalone page instead. The same
  handler serves it at `/_hackerpot/`.

Everything the handler enforces still applies: `auth`, `allowedClients`, `allowedHosts`, the throttle,
[redaction](dashboard.md#redaction) and [sections](dashboard.md#sections-withheld-on-the-server).

## Same origin only

**`src` must be a path on this page's origin.** The dashboard sends no CORS headers, which is what stops
another site reading your attackers through a logged-in browser, so a cross-origin `src` cannot work. The
element does not try: it refuses with a message naming both origins rather than failing as "Failed to
fetch". Mount `createDashboardHandler` on the server that serves your admin page.

Only the path of `src` means anything. A query string or fragment is dropped with a warning; in
particular a `?token=` is not carried along, and a token in the host page's own address is not picked
up either. Authentication belongs in the handler's `auth`: a cookie, or the session the page already has.

A handler with `auth` answers the element's background fetch with `401`, and a background fetch cannot
raise the browser's sign-in prompt. Either sign in once by opening the handler's own URL (the browser
then sends those credentials with the element's requests), put the host page behind the same credential
as the demo does, or use an `authorize` check that reads the session the page already has.

---

## Attributes

| Attribute | Values | |
| --- | --- | --- |
| `src` | a same-origin path | where `createDashboardHandler` is mounted, e.g. `/_hackerpot`. Read once, when the element first mounts. |
| `scheme` | `light`, `dark` | force a colour scheme; unset follows the viewer's setting |
| `density` | `comfortable`, `compact` | `compact` tightens table rows and panel padding |

```html
<hackerpot-dashboard src="/_hackerpot" scheme="dark" density="compact"></hackerpot-dashboard>
```

Any other `scheme` or `density` is ignored with one console warning. The same settings in
`config.theme` take precedence over the attributes.

## The `config` property

For anything more than a template can say:

```js
const node = document.querySelector("hackerpot-dashboard");
node.config = {
  src: "/_hackerpot",
  tabs: [{ id: "overview" }, { id: "incidents", label: "Hits" }, { id: "sessions" }],
  theme: { density: "compact", tokens: { accent: "#7c3aed" } },
  view: { tab: "incidents", detector: "honeytoken" },
  panels: [
    { id: "waf", screen: "overview", title: "Edge firewall", source: "/admin/api/waf", refreshMs: 30_000 },
  ],
};
defineHackerpotDashboard();
```

| Field | | Changes after mount |
| --- | --- | --- |
| `src` | overrides the attribute | no |
| `tabs` | which screens appear, in what order, under what labels | no; warns |
| `hide` | screens to hide (cosmetic) | no; warns |
| `panels` | panels of your own | no; warns |
| `theme` | `tokens`, `scheme`, `density` | **yes, immediately** |
| `view` | where it opens | read on the first frame |

**Set `config` before or after `defineHackerpotDashboard()`; both work.** It is an accessor, so a value
written on the element before it upgrades is reclaimed at upgrade rather than overwritten. The demo sets
it first.

Re-assigning an equivalent config, which a framework does on every render, is silent: the comparison is
by the screens, hides and panel placements it describes, not by object identity, and panel `source`
functions rebuilt on every render do not count as a change. A real change to `tabs`, `hide` or `panels`
after mount says in the console that it had no effect; remount the element instead.

`defineHackerpotDashboard(name?)` registers the element, `hackerpot-dashboard` by default. It is safe to
call more than once. The element dispatches `hackerpot-dashboard-ready` (bubbling) when it has drawn,
including after a remount.

---

## Choosing the screens

```js
config = { tabs: [{ id: "overview", label: "Summary" }, { id: "incidents" }] };
```

Six screens exist, and their ids are the server's section names: `overview`, `incidents`, `statistics`,
`sessions`, `actors`, `intel`. So the word in `tabs` is the word in `hide` and the word in the handler's
`sections`. Listing screens chooses which appear, their order and their labels; a screen left out is
not shown.

Three rules decide what you get:

1. **A section the server withheld cannot come back.** `tabs` listing it warns that the section is
   switched off on the server, and where to look.
2. **`hide` wins over `tabs`.** An explicit instruction to hide something is not overridden by its
   appearing in a list, and the console says so.
3. **An unknown id does nothing,** and the warning lists the screens that exist.

### Hiding is not withholding

```js
config = { hide: { intel: true } };   // off the screen, still on the wire
```

`hide` and `tabs` narrow what is drawn. The browser still receives the data, and anyone with devtools can
read it. The handler's [`sections`](dashboard.md#sections-withheld-on-the-server) option is the one that
keeps data in the process; use it when the point is that somebody should not have it.

## Where it opens

The standalone page keeps its tab in the URL fragment (`#incidents`). Embedded, the address bar belongs to
your page and the element never writes to it, so say it in the config:

```js
config = { view: { tab: "incidents", ip: "203.0.113.7", detector: "web-shell" } };
```

| Field | Sets |
| --- | --- |
| `tab` | the screen to open on; must be one that survives `tabs`, `hide` and the server's sections |
| `ip` | the Incidents screen's source-address filter |
| `detector` | the Incidents screen's detector filter |

A starting point, not a restriction: everything here can be changed on screen. An unusable `tab` opens on
the first screen and says why; `ip` or `detector` without an Incidents screen warns that they do nothing.

## Theming

```js
config = {
  theme: {
    scheme: "light",
    density: "compact",
    tokens: { accent: "#7c3aed", surface: "#ffffff", text: "#1a1a2e" },
  },
};
```

Tokens are the stylesheet's custom properties (`accent`, `link`, `text`, `muted`, `surface`, `page`,
`header-bg` and the rest in `src/dashboard/page.ts`), named with or without the leading dashes. They are
set on the host element and inherit into the shadow root. A name that is not a plain custom-property name
is ignored with a warning. A token dropped from a later `theme` is removed from the element, so switching
themes gives you the new theme, not the union of every theme you set. `theme` updates live.

The shipped palette was measured for contrast in both schemes. Replace a token and that measurement is
yours to redo.

The **Theme** button in the dashboard's header still works, and remembers the viewer's choice in
`localStorage`. Embedded, a remembered choice does not override a scheme you set explicitly.

## Panels of your own

```js
config = {
  panels: [
    { id: "checkout", screen: "overview", title: "Checkout health", source: "/admin/api/checkout", refreshMs: 15_000 },
    { id: "queue", screen: "incidents", title: "Queue depth", source: () => ({ rows: [{ label: "Pending", value: pending.length }] }) },
  ],
};
```

A panel is drawn at the end of one screen. Its `source` is a same-origin URL answering
`{ rows: [{ label, value, note? }] }`, or a function (sync or async) returning the same.

- **Rows are text, always.** A value containing a tag appears as that tag rather than becoming one.
  Objects are shown as JSON; each cell is cut at 200 characters.
- **At most 200 rows** are drawn, followed by "N more not shown".
- **`refreshMs`** reloads it on an interval of at least one second; omit it to load once. The timer stops
  when the element is removed.
- **Failures say so in place**: "Could not load Checkout health." for a source that throws or a URL that
  fails, "Checkout health returned no rows." for anything that is not `{ rows: [...] }`.
- A panel naming a screen that is not shown, a URL source on another origin, and two panels with the same
  id on one screen each warn in the console, and that panel is skipped.

---

## Content-Security-Policy for the host page

The element needs no inline script and no inline style. Its stylesheet is a constructable stylesheet
adopted into the shadow root, which `style-src 'self'` does not block, and its markup is parsed with
`DOMParser`, which runs nothing. It fetches only same-origin URLs, so `connect-src 'self'` (or
`default-src 'self'`) covers the API and the event stream.

The demo's policy is a working example:

```text
default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'
```

One exception: in a browser without constructable stylesheets the element falls back to a `<style>`
element in the shadow root, which a strict `style-src` blocks. Current Chromium, Firefox and Safari all
have them.

## Server-side rendering

Importing `@osqd/hackerpot/element` where there is no DOM is safe. The class extends a stand-in when
`HTMLElement` does not exist, and `defineHackerpotDashboard()` does nothing without a custom-element
registry. Write the import at the top of a component and call it on mount.

## Remounting under a router

A router unmounts and remounts the element on navigation. The element keeps the rendered dashboard across
that: removing it closes the event stream and stops panel timers, so a page that has navigated away holds
no server connection; mounting it again re-parents the same subtree into the new element, reconnects the
stream and reloads the data. React's development double mount is the same case.

## One at a time

The client is one module graph with its own state, so two live elements would draw one feed. A second
element connected while another is running shows "A HackerPot dashboard is already running on this page.
Only one can be." Sequentially is fine: once the first is removed, a later mount takes over. One whose
start failed (a handler not yet up, a wrong `src` since corrected) tries again on its next mount.

## Version skew

The element is compiled into your front-end bundle and the handler runs in your server, so nothing makes
them the same release. The element compares its version with the one in `/api/bootstrap` and warns once:

```text
hackerpot-dashboard: this element is @osqd/hackerpot 0.2.0 and the handler at /_hackerpot is 0.1.0. They are separate bundles, so an empty panel here may be that difference rather than a fault. Install the same version in both.
```

Skew does not look like an error; it looks like a panel that stays empty because a field was renamed.

## Accessibility

Built for being a section of somebody else's page rather than the page:

- **No second `main` landmark.** The dashboard's `main` becomes a region labelled "*title* HackerPot
  dashboard".
- **No second banner.** Its header keeps its styling and gives up its landmark role.
- **It paints its own ink and surface**, since a shadow root has no `body` to inherit them from.
- **It leaves your keyboard and URL alone.** Its keyboard and pointer listeners are on its own subtree,
  not the window, and it never writes `location.hash`.

The tab strip keeps its keyboard contract (arrow keys, Home, End), incident rows open with Enter, and
every chart has a table view.

---

## Frameworks

It is a custom element, so it works wherever elements do. Set `config` as a **property**, not an
attribute: an object in an attribute becomes the string `[object Object]`.

**React**

```tsx
import { useEffect, useRef } from "react";
import { defineHackerpotDashboard, type HackerpotDashboardConfig } from "@osqd/hackerpot/element";

const config: HackerpotDashboardConfig = { tabs: [{ id: "overview" }, { id: "incidents" }], theme: { density: "compact" } };

export function Security() {
  const ref = useRef<HTMLElement & { config: HackerpotDashboardConfig }>(null);
  useEffect(() => {
    if (ref.current) ref.current.config = config;
    defineHackerpotDashboard();
  }, []);
  return <hackerpot-dashboard ref={ref} src="/_hackerpot" />;
}
```

TypeScript knows the tag through `HTMLElementTagNameMap`; for JSX, declare `hackerpot-dashboard` in your
`JSX.IntrinsicElements` once.

**Vue**

```vue
<script setup lang="ts">
import { onMounted } from "vue";
import { defineHackerpotDashboard } from "@osqd/hackerpot/element";

const config = { tabs: [{ id: "overview" }, { id: "incidents" }] };
onMounted(() => defineHackerpotDashboard());
</script>

<template>
  <hackerpot-dashboard src="/_hackerpot" :config.prop="config" />
</template>
```

Tell the compiler it is a custom element: `compilerOptions.isCustomElement: (tag) => tag ===
"hackerpot-dashboard"` in your Vue plugin options.

**A name of your own**, if `hackerpot-dashboard` is taken by something else (the element tells you rather
than doing nothing quietly):

```js
defineHackerpotDashboard("ops-hackerpot");
```

## When it does not appear

It does not fail quietly. The console, prefixed `hackerpot-dashboard:`, and a notice in the element say
which of these it was:

| What you see | What it means |
| --- | --- |
| "could not start: it answered 401 Unauthorized" | The handler has `auth` and this browser has not signed in. A background fetch cannot raise the prompt; open the handler's URL once, or use an `authorize` that reads the page's session. |
| "it answered 403 Forbidden" | `allowedClients` refused this client, or the request was not same-origin. |
| "it answered 421 Misdirected Request" | The handler's `allowedHosts` does not include this page's host name. |
| "it answered 404 at /_hackerpot/api/bootstrap" | Nothing is mounted there. |
| "it answered 429" | Too many failed sign-ins from this address. Wait, then reload. |
| "no `src` was given, so it asked this page's own origin and got something other than JSON back" | Set `src`. |
| "it answered text/html rather than JSON. Is createDashboardHandler mounted at …?" | `src` points at a page of yours, not the handler. |
| "src points at …, which is not this page's origin" | Same origin only. Mount the handler here and use a path. |
| "src … has a query string on it" | Only the path is used. |
| "A HackerPot dashboard is already running on this page" | Two elements at once. |
| "&lt;hackerpot-dashboard&gt; is already registered on this page by something else" | Use `defineHackerpotDashboard("your-name")`. |
| "tabs lists "x", which is not a screen" | The screens are `overview`, `incidents`, `statistics`, `sessions`, `actors`, `intel`. |
| "tabs lists "x", but this dashboard's server has the "x" section switched off" | `sections` on the handler; not something the page can override. |
| "hide.x is not a screen, so it did nothing" | `hide` takes the same six ids. |
| "`tabs`, `hide` and `panels` are read once" | Remount to change them; `theme` updates live. |
| "`src` is read once" | Replace the element to point it elsewhere. |
| "panel "x" asks for screen "y", which this dashboard does not show" | A typo in `screen`, or the screen is hidden. |
| "this element is @osqd/hackerpot … and the handler at … is …" | [Version skew](#version-skew). |
| "this page is framed by another origin" | Send `frame-ancestors 'none'` on the host page. |

---

## Related

- [The dashboard](dashboard.md): every option, the security model, and what each screen shows
- [Operations](index.md): where incidents go
- [Try it locally](../testing/try-it.md): `npm run demo:embedded` beside the other demos
