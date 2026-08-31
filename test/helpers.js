/**
 * Shared fixtures and stubs. Everything here is offline and synchronous.
 *
 * The suite plants a **fixed** canary rather than letting the plugin mint one,
 * because a random plant would make every assertion below a coin flip: the
 * value that must appear in one place and must not appear in six others has to
 * be the same value the test can look for. `config.canary` exists for exactly
 * this, and the tests are the first consumer of it.
 *
 * `FIXED_CANARY` was never a live plant anywhere. It is the right *shape* — the
 * tag plus 32 hex — and nothing else.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/** The deterministic plant every test uses. */
export const FIXED_CANARY = `DSHCANARY_${'0123456789abcdef'.repeat(2)}`

/** A second fixed plant, for asserting that two sessions do not share one. */
export const OTHER_CANARY = `DSHCANARY_${'fedcba9876543210'.repeat(2)}`

/** The first twelve characters of {@link FIXED_CANARY}: all the status tool may say. */
export const FIXED_PREFIX = 'DSHCANARY_01'

/**
 * Strings that are canary-adjacent and must pass through untouched, so a
 * passing suite means "this exact value and not anything resembling it".
 *
 * A false trip denies a legitimate tool call, which is the failure mode that
 * would get this plugin switched off — so near misses are tested as carefully
 * as hits.
 */
export const NEAR_MISSES = Object.freeze([
  'DSHCANARY_',
  FIXED_CANARY.slice(0, -1),
  FIXED_CANARY.slice(1),
  FIXED_CANARY.toUpperCase(),
  `${FIXED_CANARY.slice(0, 20)} ${FIXED_CANARY.slice(20)}`,
  'a sentence mentioning a canary',
  'https://example.com/path?query=1',
])

/**
 * A context stub exposing only what `apply` is allowed to touch.
 * @returns The stub context and the definitions it recorded.
 */
export function stubContext() {
  const registered = []
  const ctx = {
    tools: {
      register(definition) {
        registered.push(definition)
        return () => {}
      },
    },
  }
  return { ctx, registered }
}

/** The execution context the registry passes to `execute`; unused by these tools. */
export const exec = { signal: new AbortController().signal }

/**
 * A private incident log path under the OS temp directory, removed afterwards.
 *
 * Tests never write into the repository: the log would otherwise be a file of
 * incident lines sitting in the tree the hygiene scan walks.
 * @param t - The running test context, used to register cleanup.
 * @returns An absolute path in a fresh directory.
 */
export function tempLog(t) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-canary-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return join(dir, 'incidents.jsonl')
}

/**
 * Assert that some text carries no trace of a canary.
 *
 * Both the whole value and its tail are checked: a message that printed all but
 * the first character would pass a whole-string check and still have handed the
 * canary back to whatever is reading it.
 * @param text - Anything renderable as a string, such as a JSONL file.
 * @param canary - The value that must be absent.
 * @param what - Named in the failure message.
 */
export function assertNoCanaryLeak(text, canary, what = 'output') {
  const haystack = typeof text === 'string' ? text : JSON.stringify(text)
  assert.equal(haystack.includes(canary), false, `${what} contains the whole canary`)
  assert.equal(
    haystack.includes(canary.slice(-16)),
    false,
    `${what} contains the tail of the canary`,
  )
}
