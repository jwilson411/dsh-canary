# dsh-canary

A **DeepSeek Harness function plugin** that plants a canary string in
model-visible context and **denies any tool call whose arguments or outbound URL
echo it back**. The denial happens *before* the tool runs, carries
`code: 'CANARY_TRIP'`, and appends one JSONL line that does not contain the
canary.

The plant looks like this — the tag, then 32 hex characters:

```
DSHCANARY_…
```

Nothing legitimate in a session ever carries that value. It is not an argument
to anything, not an identifier, and not data. So a tool call holding it is not
ambiguous: something read the context and tried to send it somewhere.

## What it is and is not

> **This detects echo-exfil of this planted canary. It does not detect prompt
> injection in general, and it is not a red-team product.**

- **Not a prompt-injection detector.** It catches one behaviour: the planted
  canary being repeated into a tool argument or a URL. An injection that
  exfiltrates your *actual* data, edits a file, or persuades the model to skip a
  step is invisible here — the canary was never involved. A clean incident log
  means this canary was not echoed, and nothing more.
- **Not a red-team product.** There are no attack payloads in this repository,
  no jailbreak corpus, no injection generator, and nothing that targets any
  harness. It ships a tripwire and a guard; producing something to trip them is
  not its job and not in the tree.
- **Not a classifier.** The check is a substring match against one exact value.
  There is no model, no scoring, no entropy heuristic, and no threshold to tune.
  A near miss — a truncated canary, a different case, the value split across two
  fields — does **not** trip it, on purpose: a false trip denies a legitimate
  call, which is the failure mode that gets a plugin like this switched off.
- **Not a covert control.** The canary is planted in a tool description the
  model can read, together with the instruction not to echo it and the statement
  that echoing it will be denied. A model that trips this has been told, in the
  same context, exactly what would happen.
- **Not data-loss prevention.** It watches one seam — the arguments handed to a
  wrapped tool, and URLs you check — and nothing else. It does not watch files,
  egress, or a mail flow.

A trip is **strong evidence** that context reached an outbound argument. No trip
is **not** evidence that nothing did.

## Install

```sh
dsh plugin --profile default add github:jwilson411/dsh-canary
```

`dsh plugin` forwards to pnpm inside `$DSH_HOME/profiles/default`, then
reconciles the profile: because this package's manifest declares
`dsh.bundle.patch`, it is appended to the profile manifest's ordered
`dsh.profile.bundles` list and its `cordis.patch.yml` becomes a layer. Remove it
the same way, with `remove` in place of `add`.

## Pinned DSH release candidate

This package is written and tested against the pinned release candidate
**`0.1.1-rc.2`** — `@deepseek-ai/dsh-tools@0.1.1-rc.2` is pinned exactly in
`devDependencies` so tests run against one known API, and the peer range is
`^0.1.1-rc.2`, matching how the harness's own tool packages declare it.

## The two seams this RC does not have, and what is done instead

The pinned release candidate exposes **no system-prompt inject seam** and **no
tool-execute middleware seam**. This package does not invent either one, and
reaches into no private API.

| what is needed | what the RC offers | what this package does |
|---|---|---|
| put the canary where the model reads it | no prompt inject seam | registers `canary_context`, whose **description** carries the canary. A tool description is model-visible by construction. |
| deny a call before it executes | no execute middleware seam | exports `wrapExecute`, applied by the **host** at its own call site. |

The plant is therefore exactly as durable as the tool registry: registration
happens inside `apply`, so the Cordis fiber owns it, and stopping, updating, or
reloading the plugin retires the plant with no bookkeeping.

## What it registers

| | |
|---|---|
| Cordis plugin id | `canary` (the row id in `cordis.patch.yml`) |
| Injects | `tools` — a hard dependency; the plugin waits rather than degrading |
| Tools | `canary_context` (the plant), `canary_status` (the tally) |
| Arguments | neither tool takes any |

`canary_context` returns `{ planted, prefix, reminder, plugin }`. `canary_status`
returns `{ planted, prefix, incidents, lastTool, lastWhere, lastAt, log, plugin }`.

**Neither tool ever returns the canary.** `prefix` is the first **12**
characters — the ten-character tag plus two hex digits, which is enough to
confirm *which* plant is live and 120 bits short of enough to reconstruct it. A
status tool the model can call is a status tool an injected instruction can
call, so there is nothing there worth calling it for.

## The library API

The tools are the visible half. The guard is the product:

```js
import { plantCanary, wrapExecute, CanaryTripError } from 'dsh-canary'

const state = plantCanary()                       // or plantCanary({ canary })

const guarded = wrapExecute(tool.execute, state, { tool: tool.name })

try {
  await guarded(argsFromTheModel, exec)
} catch (error) {
  if (error instanceof CanaryTripError) {
    log.warn({ code: error.code, where: error.where, tool: error.tool })
    return
  }
  throw error
}
```

On a hit the inner `execute` is **never called**, one incident line is appended,
and the error propagates. On a miss the arguments are passed through untouched —
this plugin redacts nothing and rewrites nothing.

Two narrower entry points, for a host that owns a different call site:

```js
import { assertNoCanary, assertNoCanaryInUrl } from 'dsh-canary'

assertNoCanary(requestBody, state, { tool: 'http' })   // throws on a hit
assertNoCanaryInUrl(candidate, state, { tool: 'fetch' })
```

Both throw and write nothing; `wrapExecute` owns the incident so that one
denial is one line whichever a host reaches for. `scan(value, canary)` is the
same walk exposed on its own, returning `{ where, path }` or `null`.

## What counts as an echo

The walk covers strings, arrays, and plain objects, and it scans object **keys**
as well as values — a payload keyed by the canary leaks it as surely as one that
holds it. Cyclic structures are walked once, not forever.

`where` is reported as **`url`** when the hit is:

- under a key named `url`, `uri`, or `href` (case-insensitively), at any depth;
- inside a string that *is* an absolute URL — one beginning with a scheme —
  wherever in the arguments that string sits;
- in the path, query, fragment, userinfo, or host of such a URL;
- in any of the above after **percent-decoding**, up to two passes — a canary
  pasted into a query string arrives encoded, and that is the exfil working.

and **`args`** otherwise — a URL embedded in a longer piece of prose is denied
like anything else, and recorded as `args`, because `where` names the field the
echo sat in rather than scraping URLs out of text. A `url` hit anywhere in the
walk wins over an `args` hit, because the outbound surface is the one worth
naming.

Absolute-URL detection here is deliberately shape-based rather than a fetchable
check: `data:` and `javascript:` are URLs for this purpose. Whether a URL *may*
be opened is a different question, for a different plugin.

## The error

```js
error instanceof CanaryTripError
error.code    // 'CANARY_TRIP' — always
error.where   // 'args' | 'url'
error.tool    // the tool whose call was denied
error.prefix  // the first 12 characters of the canary, never more
error.path    // dotted path to the offending field, or null
error.message // human-readable, and canary-free
```

The message carries the prefix and never the value. An error message is the
thing most likely to be logged, rendered, or handed straight back to the model
that just tried to exfiltrate the canary; putting the canary in it would hand
over the answer.

## The incident log

Append-only JSONL, created `0600`, one line per denied call:

```json
{"ts":"2026-08-31T12:00:00.000Z","tool":"http_get","where":"url"}
```

Three fields, and the record is **constructed from three scalars** rather than
spread from a caller's object, so there is no path by which the canary reaches
the file. `where` is validated against `args` / `url` on the way in and on the
way back out, so a log appended to by something else cannot smuggle a value into
`canary_status`.

The whole canary is emitted in exactly **one** place, once, at plant time: the
`canary_context` description. Not the log, not the status tool, not an error.

A write failure is deliberately not swallowed — a tripwire whose audit trail
silently stops is worse than one that fails loudly.

## Config

| key | type | default | |
|---|---|---|---|
| `canary` | string | generated | a fixed plant, `DSHCANARY_` + 32 lowercase hex |
| `incidentLog` | string | `.dsh-canary.jsonl` | path of the append-only JSONL log |

Set them from the profile's own `cordis.patch.yml` — note that an id-targeted
patch replaces the row's whole `config`, so restate every field you mean to
keep:

```yaml
- id: canary
  config:
    incidentLog: /var/log/dsh/canary.jsonl
```

Resolution order is **patch config, then environment, then generated**: a patch
row is the deployment's stated intent, so it is not silently overridden by an
ambient variable. The environment fallbacks are `DSH_CANARY` and
`DSH_CANARY_LOG`, each used only when the patch row omits the key entirely.

**Leave `canary` unset in production.** A fresh 128-bit canary is minted on
every apply, so a plant lasts one plugin lifetime and nobody gets a second
session to work on the same value. Fix it only when the plant must be
predictable:

- a **test suite** that has to assert on the value — this repository's own suite
  is the first consumer of the key, and every test below plants a fixed canary
  so the assertions are deterministic;
- a **fleet** of workers that must share one plant.

A configured value that is not canary-shaped is **rejected** at apply time with
an `InvalidCanaryError` rather than quietly replaced by a random one: a silent
substitution makes every downstream expectation wrong, and a short one would
match half the arguments in the session.

## Layout

```
package.json          manifest + `dsh.bundle.patch` — what makes this a bundle
cordis.patch.yml      the bundle's patch layer: one insert, one plugin row
src/canary.js         the pure half: mint, scan, deny, append
src/index.js          the plugin: `name`, `inject`, `apply(ctx, config)`, the tools
test/                 offline tests: the walk, a stub context, a hygiene scan
package-lock.json     the pinned dependency tree `npm ci` installs in CI
```

## Tests

```sh
npm install
npm test
```

Offline by construction, and not merely by intention: every case is a string
walk, `apply` is handed a stub context that records registrations, tool results
are validated against the real `@deepseek-ai/dsh-tools` pinned to `0.1.1-rc.2`,
and every incident log is written under the OS temp directory and removed
afterwards. `test/hygiene.test.js` asserts that the shipped source opens no
socket, no fetch, and no subprocess, that the tree carries no machine names,
mount paths, or credential-variable names, and that CI needs no credentials.

CI runs the same two commands on Node 22.x and 24.x with `contents: read` and no
secrets.

## Version

Initial release, 2026-08-31. MIT.
