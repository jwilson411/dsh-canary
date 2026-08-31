/**
 * The pure half of dsh-canary: mint a canary, scan a value for it, deny the
 * call that echoed it, and append a JSONL line that does not contain it.
 *
 * The whole design rests on one asymmetry. The canary is planted in
 * **model-visible context** and is never a legitimate input to any other tool,
 * so a tool argument or an outbound URL carrying it is not ambiguous: something
 * read the context and tried to send it somewhere. That makes the check a
 * substring match rather than a classifier, and makes the denial fail-closed —
 * {@link assertNoCanary} throws, so a caller cannot proceed by forgetting to
 * read a boolean.
 *
 * The second rule the file is built around: **the canary is written to disk
 * nowhere**. An incident line holds a timestamp, the tool name, and where the
 * echo was found. Not the canary, not a prefix of it beyond the shared
 * `DSHCANARY_` tag, not a hash of it. A tripwire whose log copies the tripwire
 * out into a file the model can later read is not a tripwire.
 *
 * **This detects echo-exfil of this planted canary, and nothing else.** It is
 * not a prompt-injection detector. See the README.
 *
 * @module dsh-canary/canary
 */
import { randomBytes } from 'node:crypto'
import { appendFileSync, readFileSync } from 'node:fs'

/** The npm package name, echoed by the status tool so a line names its source. */
export const PLUGIN_NAME = 'dsh-canary'

/** The `code` every denial carries, so a caller can branch without parsing prose. */
export const CANARY_TRIP = 'CANARY_TRIP'

/** The tag every canary starts with, shared by all of them and secret in none. */
export const CANARY_PREFIX = 'DSHCANARY_'

/** The exact shape of a canary, anchored: the tag plus 32 lowercase hex. */
export const CANARY_PATTERN = /^DSHCANARY_[0-9a-f]{32}$/

/**
 * How much of the canary the status tool may disclose.
 *
 * Twelve characters is the ten-character tag plus two hex digits: enough to
 * confirm *which* plant is live across a restart, and 120 bits short of enough
 * to reconstruct it. The status tool exists to answer "is a canary planted and
 * has it tripped", not "what is the canary".
 */
export const PREFIX_LENGTH = 12

/** Default incident log path, resolved against the process working directory. */
export const DEFAULT_INCIDENT_LOG = '.dsh-canary.jsonl'

/** Environment fallback for the incident log path. */
export const INCIDENT_LOG_ENV = 'DSH_CANARY_LOG'

/** Environment fallback for a fixed canary, used only when the patch row omits one. */
export const CANARY_ENV = 'DSH_CANARY'

/** Every place an echo can be found. `where` is one of these, and only these. */
export const WHERE = Object.freeze(['args', 'url'])

/** Argument keys whose value is treated as a URL whatever it looks like. */
export const URL_KEYS = Object.freeze(['url', 'uri', 'href'])

/** How many incidents `canary_status` reads back when tallying. */
export const MAX_INCIDENTS_READ = 1000

/**
 * A trip: the canary was found in something on its way out, so the call was
 * denied before it ran.
 *
 * Raised rather than returned, for the same reason the SSRF guard raises: a
 * guard a caller can walk past by ignoring a return value is not a guard. The
 * error carries the tool, the `where`, and the canary **prefix** — never the
 * canary, since the error message is the thing most likely to be logged, shown,
 * or handed back to the model that just tried to exfiltrate it.
 */
export class CanaryTripError extends Error {
  /**
   * @param where - `args` or `url`, from {@link WHERE}.
   * @param message - Human-readable detail, carrying no canary bytes.
   * @param details - `{ tool, prefix, path }` as far as they are known.
   */
  constructor(where, message, { tool = 'unknown', prefix = null, path = null } = {}) {
    super(message)
    this.name = 'CanaryTripError'
    /** Always `CANARY_TRIP`; `where` says which surface echoed it. */
    this.code = CANARY_TRIP
    /** `args` when found in an argument, `url` when found in a URL. */
    this.where = where
    /** The tool whose call was denied. */
    this.tool = tool
    /** The first {@link PREFIX_LENGTH} characters of the canary, never more. */
    this.prefix = prefix
    /** A dotted path to the offending field, for a human reading a log. */
    this.path = path
  }
}

/**
 * Raised when a configured canary is not canary-shaped.
 *
 * Generating a fresh one instead would be worse than failing: the deployment
 * asked for a specific plant, and a silent substitution means every downstream
 * expectation about that value is quietly wrong. A short or empty string is
 * worse still — it would match half the arguments in the session.
 */
export class InvalidCanaryError extends Error {
  /** @param value - The rejected configuration value, described but not echoed. */
  constructor(value) {
    super(
      `configured canary must match ${CANARY_PATTERN} — ` +
        `got a ${typeof value} of length ${typeof value === 'string' ? value.length : 0}`,
    )
    this.name = 'InvalidCanaryError'
    this.code = 'CANARY_INVALID'
  }
}

/**
 * Mint a canary: the tag plus 128 bits of hex.
 *
 * Random rather than derived, and long enough that it cannot collide with real
 * argument text — a false trip denies a legitimate tool call, which is the one
 * failure mode that would get this plugin turned off.
 * @returns A fresh `DSHCANARY_<32hex>`.
 */
export function generateCanary() {
  return `${CANARY_PREFIX}${randomBytes(16).toString('hex')}`
}

/**
 * Accept a canary-shaped string, reject anything else.
 * @param value - A candidate from config or the environment.
 * @returns The trimmed canary, or null when the value was absent or blank.
 * @throws {InvalidCanaryError} When a non-blank value is not canary-shaped.
 */
export function normalizeCanary(value) {
  if (value === undefined || value === null) return null
  if (typeof value !== 'string' || value.trim() === '') {
    if (typeof value === 'string') return null
    throw new InvalidCanaryError(value)
  }
  const trimmed = value.trim()
  if (!CANARY_PATTERN.test(trimmed)) throw new InvalidCanaryError(trimmed)
  return trimmed
}

/**
 * Resolve the canary to plant: patch config, then environment, then a fresh one.
 *
 * The patch row is the deployment's stated intent, so it wins over an ambient
 * variable. A fixed canary is what makes a test suite — or a fleet of workers
 * sharing one plant — deterministic; the generated case is the default because
 * a canary checked into a config file is a canary a model may have been trained
 * on.
 * @param config - `{ canary }` from a patch row or a call site.
 * @param env - Environment to read, injectable for tests.
 * @returns `{ canary, source }` with `source` one of `config`, `env`, `generated`.
 */
export function resolveCanary(config = {}, env = process.env) {
  const fromConfig = normalizeCanary(config?.canary)
  if (fromConfig !== null) return { canary: fromConfig, source: 'config' }

  const fromEnv = normalizeCanary(env?.[CANARY_ENV])
  if (fromEnv !== null) return { canary: fromEnv, source: 'env' }

  return { canary: generateCanary(), source: 'generated' }
}

/**
 * Resolve the incident log path: explicit, then environment, then default.
 * @param options - `{ incidentLog }` from a patch row or a call site.
 * @param env - Environment to read, injectable for tests.
 * @returns A path string; a relative one is resolved by the filesystem call.
 */
export function resolveIncidentLog(options = {}, env = process.env) {
  const explicit = options?.incidentLog
  if (typeof explicit === 'string' && explicit.trim() !== '') return explicit.trim()
  const fromEnv = env?.[INCIDENT_LOG_ENV]
  if (typeof fromEnv === 'string' && fromEnv.trim() !== '') return fromEnv.trim()
  return DEFAULT_INCIDENT_LOG
}

/**
 * The disclosable prefix of a canary.
 * @param canary - The planted canary.
 * @returns Its first {@link PREFIX_LENGTH} characters, or `''` for a non-string.
 */
export function canaryPrefix(canary) {
  return typeof canary === 'string' ? canary.slice(0, PREFIX_LENGTH) : ''
}

/**
 * Plant a canary and open the session that guards it.
 *
 * "Planting" is one thing: the returned state carries the canary, and
 * `createCanaryContextTool` puts it into a tool description the model can read.
 * That description is the **only** place the whole canary is emitted, and it is
 * built once, here, at plant time. Nothing else in this package writes it
 * anywhere — not the incident log, not the status tool, not an error message.
 * @param options - `{ canary, incidentLog, env }`.
 * @returns The state to thread through {@link wrapExecute} and the tools.
 */
export function plantCanary(options = {}, env = process.env) {
  const { canary, source } = resolveCanary(options, env)
  return {
    canary,
    prefix: canaryPrefix(canary),
    source,
    incidentLog: resolveIncidentLog(options, env),
  }
}

/**
 * Whether a value is a plain object this module is willing to walk into.
 *
 * Class instances, Maps, Buffers, and Dates are stepped over rather than
 * enumerated as if they were object literals.
 * @param value - Any value.
 * @returns True for object literals and null-prototype objects.
 */
function isPlainObject(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

/**
 * Whether a string reads as an absolute URL.
 *
 * Deliberately shape-based rather than a parse: `javascript:` and `data:` URLs
 * are URLs for this purpose too, and the question here is only "should the
 * echo be reported as `url` rather than `args`", never "may this be fetched".
 * That second question belongs to a different plugin.
 * @param text - A candidate string.
 * @returns True when it starts with a scheme.
 */
export function looksLikeUrl(text) {
  return typeof text === 'string' && /^[a-z][a-z0-9+.-]*:/i.test(text.trim())
}

/**
 * Every reading of a string worth scanning: the string itself, plus what it
 * decodes to.
 *
 * A canary pasted into a query parameter arrives percent-encoded, so the raw
 * bytes no longer contain it — `?q=DSHCANARY%5F…` is the exfil working. Both
 * the whole string and each URL component are decoded, because a decode of the
 * whole string fails on a stray `%` that a component-wise decode survives.
 * @param text - The candidate string.
 * @returns Distinct readings, always including the original.
 */
function readings(text) {
  const out = [text]

  const decoded = safeDecode(text)
  if (decoded !== null && decoded !== text) out.push(decoded)

  if (looksLikeUrl(text)) {
    for (const part of urlParts(text)) {
      if (!out.includes(part)) out.push(part)
      const decodedPart = safeDecode(part)
      if (decodedPart !== null && !out.includes(decodedPart)) out.push(decodedPart)
    }
  }

  return out
}

/**
 * Percent-decode, twice, tolerating malformed input.
 *
 * Twice because a double-encoded canary is still a canary on arrival at
 * whatever finally decodes it, and the cost of one extra pass is nothing.
 * @param text - The candidate string.
 * @returns The decoded string, or null when it does not decode.
 */
function safeDecode(text) {
  try {
    const once = decodeURIComponent(text)
    try {
      return decodeURIComponent(once)
    } catch {
      return once
    }
  } catch {
    return null
  }
}

/**
 * The path, query, and fragment of a URL, plus each query value on its own.
 * @param text - A string that looked like a URL.
 * @returns The components worth scanning; empty when it does not parse.
 */
function urlParts(text) {
  let url
  try {
    url = new URL(text.trim())
  } catch {
    return []
  }

  const parts = [url.pathname, url.search, url.hash, url.username, url.password, url.host]
  for (const [key, value] of url.searchParams) {
    parts.push(key, value)
  }
  return parts.filter((part) => typeof part === 'string' && part !== '')
}

/**
 * Look for the canary in one string.
 * @param text - The candidate.
 * @param canary - The planted canary.
 * @returns True when any reading of the string contains it whole.
 */
export function containsCanary(text, canary) {
  if (typeof text !== 'string' || typeof canary !== 'string' || canary === '') return false
  return readings(text).some((reading) => reading.includes(canary))
}

/**
 * Walk a value looking for the canary, and report where it was found.
 *
 * Strings, arrays, and plain objects are walked; object **keys** are scanned as
 * well as values, since a payload keyed by the canary leaks it as surely as one
 * that holds it. The walk stops at the first hit: the call is denied either
 * way, and enumerating every occurrence would only build a bigger record of
 * something that must not be recorded.
 *
 * `where` is `url` when the hit was under a key named in {@link URL_KEYS} or in
 * a string that reads as a URL, and `args` otherwise. A `url` hit found
 * anywhere in the walk wins over an `args` hit, because the outbound surface is
 * the one worth naming in the incident.
 * @param value - Tool arguments, or any value on its way outbound.
 * @param canary - The planted canary.
 * @returns `{ where, path }`, or null when the canary is not there.
 */
export function scan(value, canary) {
  if (typeof canary !== 'string' || canary === '') return null

  const seen = new Set()
  let fallback = null

  /**
   * @param node - The value under inspection.
   * @param path - Dotted path from the root, for the error and nothing else.
   * @param urlish - Whether an enclosing key marked this subtree as a URL.
   * @returns A `url` hit to stop on, or null to keep walking.
   */
  function visit(node, path, urlish) {
    if (typeof node === 'string') {
      if (!containsCanary(node, canary)) return null
      const where = urlish || looksLikeUrl(node) ? 'url' : 'args'
      if (where === 'url') return { where, path }
      fallback ??= { where, path }
      return null
    }

    if (Array.isArray(node)) {
      if (seen.has(node)) return null
      seen.add(node)
      for (const [index, item] of node.entries()) {
        const hit = visit(item, `${path}[${index}]`, urlish)
        if (hit !== null) return hit
      }
      return null
    }

    if (isPlainObject(node)) {
      if (seen.has(node)) return null
      seen.add(node)
      for (const [key, item] of Object.entries(node)) {
        const child = path === '' ? key : `${path}.${key}`
        if (containsCanary(key, canary)) fallback ??= { where: 'args', path: child }
        const hit = visit(item, child, urlish || URL_KEYS.includes(key.toLowerCase()))
        if (hit !== null) return hit
      }
      return null
    }

    return null
  }

  return visit(value, '', false) ?? fallback
}

/**
 * Append one incident to the JSONL log.
 *
 * The record is **constructed here from three scalars**, never spread from a
 * caller's object, so there is no path by which the canary reaches the file:
 * `ts`, `tool`, and `where`, and `where` is checked against {@link WHERE}. The
 * file is created `0600` and only ever appended to. A write failure is not
 * swallowed — a tripwire whose audit trail silently stops is worse than one
 * that fails loudly.
 * @param path - The log path.
 * @param incident - `{ ts, tool, where }`; `ts` defaults to now.
 * @returns The record as written.
 */
export function appendIncident(path, incident = {}) {
  const record = {
    ts: typeof incident.ts === 'string' ? incident.ts : new Date().toISOString(),
    tool: typeof incident.tool === 'string' && incident.tool !== '' ? incident.tool : 'unknown',
    where: WHERE.includes(incident.where) ? incident.where : 'args',
  }
  appendFileSync(path, `${JSON.stringify(record)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'a' })
  return record
}

/**
 * Reduce one stored line to exactly the three public fields, or reject it.
 *
 * Nothing but these three ever reaches a caller of {@link readIncidents}, so a
 * log appended to by something else cannot smuggle a canary back out through
 * the status tool.
 * @param parsed - A parsed line.
 * @returns The clean record, or null.
 */
function sanitizeIncident(parsed) {
  if (!isPlainObject(parsed)) return null
  const { ts, tool, where } = parsed
  if (typeof ts !== 'string' || typeof tool !== 'string') return null
  if (!WHERE.includes(where)) return null
  return { ts, tool, where }
}

/**
 * Read the tail of the incident log.
 * @param path - The log path. A missing file reads as no incidents.
 * @param limit - How many of the most recent lines to return.
 * @returns The last `limit` well-formed incidents, oldest first.
 */
export function readIncidents(path, limit = MAX_INCIDENTS_READ) {
  let text
  try {
    text = readFileSync(path, 'utf8')
  } catch (error) {
    if (error?.code === 'ENOENT') return []
    throw error
  }

  const incidents = []
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue
    let parsed
    try {
      parsed = JSON.parse(line)
    } catch {
      // A torn last line is skipped, not fatal: the log is append-only and a
      // reader must survive a partial write.
      continue
    }
    const clean = sanitizeIncident(parsed)
    if (clean !== null) incidents.push(clean)
  }

  const count = Math.max(0, Math.min(limit, incidents.length))
  return incidents.slice(incidents.length - count)
}

/**
 * Summarize the log for {@link createCanaryStatusTool}.
 * @param path - The log path.
 * @returns `{ incidents, lastTool, lastAt, lastWhere }`; nulls when empty.
 */
export function summarizeIncidents(path) {
  const incidents = readIncidents(path)
  const last = incidents.at(-1) ?? null
  return {
    incidents: incidents.length,
    lastTool: last?.tool ?? null,
    lastAt: last?.ts ?? null,
    lastWhere: last?.where ?? null,
  }
}

/**
 * Throw if the canary is anywhere in a value. The guard, on its own.
 *
 * Call it at any point where something built from model output is about to
 * leave the process. It writes nothing: {@link wrapExecute} owns the incident
 * so one denial is one line, whichever of the two a host reaches for.
 * @param value - Tool arguments, a request body, anything.
 * @param state - The state from {@link plantCanary}.
 * @param meta - `{ tool }`, named in the error.
 * @throws {CanaryTripError} When the canary is found.
 */
export function assertNoCanary(value, state, meta = {}) {
  const hit = scan(value, state?.canary)
  if (hit === null) return

  const tool = typeof meta.tool === 'string' ? meta.tool : 'unknown'
  throw new CanaryTripError(
    hit.where,
    `canary trip: the planted canary (${canaryPrefix(state?.canary)}…) was echoed into ` +
      `${hit.where === 'url' ? 'an outbound URL' : 'the arguments'} of tool "${tool}"` +
      `${hit.path === '' ? '' : ` at ${hit.path}`}; the call was denied`,
    { tool, prefix: canaryPrefix(state?.canary), path: hit.path === '' ? null : hit.path },
  )
}

/**
 * Throw if the canary is anywhere in a URL. The same guard, for one string.
 *
 * A `where` of `url` is forced: a bare string handed to this helper is an
 * outbound URL by the caller's own account, whether or not it parses as one.
 * @param url - The URL about to be opened.
 * @param state - The state from {@link plantCanary}.
 * @param meta - `{ tool }`, named in the error.
 * @throws {CanaryTripError} When the canary is found.
 */
export function assertNoCanaryInUrl(url, state, meta = {}) {
  assertNoCanary({ url }, state, meta)
}

/**
 * Wrap one tool's `execute` so an echoed canary denies the call.
 *
 * The scan runs **before** `execute` — that is the entire point. On a hit the
 * inner function is never called, one incident line is appended, and the error
 * propagates; on a miss the arguments are passed through untouched, since this
 * plugin redacts nothing and rewrites nothing.
 *
 * This is the seam the pinned release candidate `0.1.1-rc.2` does not provide:
 * there is no tool-execute middleware to register against, so the wrapper is
 * exported for a host to apply where it owns the call, and nothing here
 * pretends otherwise.
 * @param execute - The original `execute(args, exec)`.
 * @param state - The state from {@link plantCanary}.
 * @param meta - `{ tool, incidentLog, env }`; the log defaults to the state's.
 * @returns A drop-in replacement `execute`.
 */
export function wrapExecute(execute, state, meta = {}) {
  const tool = typeof meta.tool === 'string' ? meta.tool : 'unknown'
  const path = resolveIncidentLog(
    { incidentLog: meta.incidentLog ?? state?.incidentLog },
    meta.env ?? process.env,
  )

  return async function canaryGuardedExecute(args, exec) {
    try {
      assertNoCanary(args, state, { tool })
    } catch (error) {
      if (!(error instanceof CanaryTripError)) throw error
      appendIncident(path, { tool, where: error.where })
      throw error
    }

    return execute(args, exec)
  }
}
