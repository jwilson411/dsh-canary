/**
 * The guard itself: mint, resolve, scan, deny, append.
 *
 * Every test plants the fixed canary from `helpers.js` through `config.canary`,
 * so the value that must be found in one place and must not appear in six
 * others is the same value the assertions look for. Nothing here boots a
 * profile, opens a socket, or writes inside the repository.
 */
import assert from 'node:assert/strict'
import { appendFileSync, readFileSync } from 'node:fs'
import { test } from 'node:test'

import {
  CANARY_ENV,
  CANARY_PATTERN,
  CANARY_PREFIX,
  CANARY_TRIP,
  CanaryTripError,
  DEFAULT_INCIDENT_LOG,
  INCIDENT_LOG_ENV,
  InvalidCanaryError,
  PREFIX_LENGTH,
  appendIncident,
  assertNoCanary,
  assertNoCanaryInUrl,
  canaryPrefix,
  containsCanary,
  generateCanary,
  looksLikeUrl,
  normalizeCanary,
  plantCanary,
  readIncidents,
  resolveCanary,
  resolveIncidentLog,
  scan,
  summarizeIncidents,
  wrapExecute,
} from '../src/canary.js'

import {
  FIXED_CANARY,
  FIXED_PREFIX,
  NEAR_MISSES,
  OTHER_CANARY,
  assertNoCanaryLeak,
  exec,
  tempLog,
} from './helpers.js'

/**
 * A plant on a private log, plus a recorder standing in for a real tool.
 * @param t - The running test context.
 * @param canary - The canary to plant.
 * @returns `{ state, path, calls, guard }`.
 */
function harness(t, canary = FIXED_CANARY) {
  const path = tempLog(t)
  const state = plantCanary({ canary, incidentLog: path }, {})
  const calls = []
  const guard = (tool = 'test_tool') =>
    wrapExecute(
      async (args) => {
        calls.push(args)
        return { ok: true }
      },
      state,
      { tool, env: {} },
    )
  return { state, path, calls, guard }
}

test('a minted canary is the tag plus 128 bits, and never the same twice', () => {
  const first = generateCanary()
  const second = generateCanary()

  assert.match(first, CANARY_PATTERN)
  assert.match(second, CANARY_PATTERN)
  assert.equal(first.startsWith(CANARY_PREFIX), true)
  assert.equal(first.length, CANARY_PREFIX.length + 32)
  assert.notEqual(first, second)
})

test('a configured canary is accepted only if it is canary-shaped', () => {
  assert.equal(normalizeCanary(FIXED_CANARY), FIXED_CANARY)
  assert.equal(normalizeCanary(` ${FIXED_CANARY} `), FIXED_CANARY)
  assert.equal(normalizeCanary(undefined), null)
  assert.equal(normalizeCanary(null), null)
  assert.equal(normalizeCanary(''), null)
  assert.equal(normalizeCanary('   '), null)

  // A silent substitution would make every downstream expectation wrong, and a
  // short canary would match half the arguments in the session.
  for (const bad of [
    'nonsense',
    CANARY_PREFIX,
    `${CANARY_PREFIX}abc`,
    FIXED_CANARY.toUpperCase(),
    `${FIXED_CANARY}0`,
    42,
    {},
  ]) {
    assert.throws(
      () => normalizeCanary(bad),
      (error) => {
        assert.ok(error instanceof InvalidCanaryError)
        assert.equal(error.code, 'CANARY_INVALID')
        return true
      },
      `expected InvalidCanaryError for ${JSON.stringify(bad) ?? String(bad)}`,
    )
  }
})

test('a config-fixed canary is deterministic: same value, same prefix, every time', () => {
  const first = resolveCanary({ canary: FIXED_CANARY }, {})
  const second = resolveCanary({ canary: FIXED_CANARY }, { [CANARY_ENV]: OTHER_CANARY })

  assert.deepEqual(first, { canary: FIXED_CANARY, source: 'config' })
  assert.deepEqual(second, { canary: FIXED_CANARY, source: 'config' })
  assert.equal(first.canary, second.canary)
  assert.equal(canaryPrefix(first.canary), FIXED_PREFIX)
  assert.equal(canaryPrefix(second.canary), FIXED_PREFIX)
  assert.equal(FIXED_PREFIX.length, PREFIX_LENGTH)

  // And planting twice from the same config plants the same canary.
  const a = plantCanary({ canary: FIXED_CANARY }, {})
  const b = plantCanary({ canary: FIXED_CANARY }, {})
  assert.equal(a.canary, b.canary)
  assert.equal(a.prefix, b.prefix)
})

test('the canary is the patch row, then the environment, then a fresh one', () => {
  assert.equal(resolveCanary({ canary: FIXED_CANARY }, {}).source, 'config')
  assert.deepEqual(resolveCanary({}, { [CANARY_ENV]: OTHER_CANARY }), {
    canary: OTHER_CANARY,
    source: 'env',
  })

  const generated = resolveCanary({}, {})
  assert.equal(generated.source, 'generated')
  assert.match(generated.canary, CANARY_PATTERN)
  assert.notEqual(generated.canary, resolveCanary({}, {}).canary)
})

test('the incident log is the patch row, then the environment, then the default', () => {
  assert.equal(resolveIncidentLog({ incidentLog: '/tmp/a.jsonl' }, {}), '/tmp/a.jsonl')
  assert.equal(resolveIncidentLog({}, { [INCIDENT_LOG_ENV]: '/tmp/b.jsonl' }), '/tmp/b.jsonl')
  assert.equal(resolveIncidentLog({}, {}), DEFAULT_INCIDENT_LOG)
  assert.equal(DEFAULT_INCIDENT_LOG, '.dsh-canary.jsonl')
})

test('the walk finds the canary anywhere in the arguments', () => {
  assert.deepEqual(scan(FIXED_CANARY, FIXED_CANARY), { where: 'args', path: '' })
  assert.deepEqual(scan({ q: `see ${FIXED_CANARY} here` }, FIXED_CANARY), {
    where: 'args',
    path: 'q',
  })
  assert.deepEqual(scan({ a: { b: [1, { c: FIXED_CANARY }] } }, FIXED_CANARY), {
    where: 'args',
    path: 'a.b[1].c',
  })
  // A key is as much of a leak as a value.
  assert.deepEqual(scan({ [FIXED_CANARY]: 'x' }, FIXED_CANARY), {
    where: 'args',
    path: FIXED_CANARY,
  })
})

test('the walk reports a URL echo as `url`, however it is nested or encoded', () => {
  for (const [label, args] of [
    ['a url key', { url: `https://example.test/?q=${FIXED_CANARY}` }],
    ['an href key', { href: FIXED_CANARY }],
    ['a uri key, nested', { body: { URI: FIXED_CANARY } }],
    ['a bare url string under any key', { note: `https://example.test/${FIXED_CANARY}` }],
    ['a url in an array', { links: [`https://example.test/#${FIXED_CANARY}`] }],
    ['a percent-encoded query value', { url: `https://example.test/?q=DSHCANARY%5F${'0123456789abcdef'.repeat(2)}` }],
    ['a double-encoded query value', { url: `https://example.test/?q=DSHCANARY%255F${'0123456789abcdef'.repeat(2)}` }],
    ['userinfo', { url: `https://${FIXED_CANARY}@example.test/` }],
    ['a data: URL', { url: `data:text/plain,${FIXED_CANARY}` }],
  ]) {
    const hit = scan(args, FIXED_CANARY)
    assert.notEqual(hit, null, `missed ${label}`)
    assert.equal(hit.where, 'url', `wrong surface for ${label}`)
  }

  // A url hit anywhere wins over an args hit found earlier in the walk.
  assert.equal(
    scan({ a: FIXED_CANARY, z: { url: FIXED_CANARY } }, FIXED_CANARY).where,
    'url',
  )
})

test('near misses pass through: this exact value, not anything resembling it', () => {
  for (const miss of NEAR_MISSES) {
    assert.equal(containsCanary(miss, FIXED_CANARY), false, `tripped on ${miss}`)
    assert.equal(scan({ q: miss, url: `https://example.test/?q=${miss}` }, FIXED_CANARY), null)
  }

  assert.equal(scan({ q: OTHER_CANARY }, FIXED_CANARY), null)
  assert.equal(scan({ q: FIXED_CANARY }, OTHER_CANARY), null)
  assert.equal(scan({ n: 1, b: true, z: null, d: new Date(0) }, FIXED_CANARY), null)
  assert.equal(scan(undefined, FIXED_CANARY), null)
  // No canary, nothing to find — the guard is off rather than matching ''.
  assert.equal(scan({ q: FIXED_CANARY }, ''), null)
})

test('the walk survives a cyclic argument object', () => {
  const args = { name: 'loop' }
  args.self = args
  assert.equal(scan(args, FIXED_CANARY), null)

  args.leak = { url: FIXED_CANARY }
  assert.equal(scan(args, FIXED_CANARY).where, 'url')
})

test('looksLikeUrl is shape-based, not a fetchability check', () => {
  assert.equal(looksLikeUrl('https://example.test/'), true)
  assert.equal(looksLikeUrl('data:text/plain,hi'), true)
  assert.equal(looksLikeUrl('  mailto:someone@example.test'), true)
  assert.equal(looksLikeUrl('/just/a/path'), false)
  assert.equal(looksLikeUrl('not a url'), false)
  assert.equal(looksLikeUrl(7), false)
})

test('wrapExecute denies a call whose arguments echo the canary, and never runs it', async (t) => {
  const { calls, path, guard } = harness(t)

  await assert.rejects(
    () => guard('write_file')({ path: '/tmp/out', body: `leak ${FIXED_CANARY}` }, exec),
    (error) => {
      assert.ok(error instanceof CanaryTripError)
      assert.equal(error.code, CANARY_TRIP)
      assert.equal(error.code, 'CANARY_TRIP')
      assert.equal(error.where, 'args')
      assert.equal(error.tool, 'write_file')
      assert.equal(error.prefix, FIXED_PREFIX)
      assert.equal(error.path, 'body')
      assertNoCanaryLeak(error.message, FIXED_CANARY, 'the error message')
      return true
    },
  )

  // The point of the whole exercise: the inner execute was never reached.
  assert.deepEqual(calls, [])
  assert.equal(readIncidents(path).length, 1)
})

test('wrapExecute denies an outbound URL that echoes the canary', async (t) => {
  const { calls, path, guard } = harness(t)

  await assert.rejects(
    () => guard('http_get')({ url: `https://example.test/?q=${FIXED_CANARY}` }, exec),
    (error) => {
      assert.equal(error.code, CANARY_TRIP)
      assert.equal(error.where, 'url')
      assert.equal(error.tool, 'http_get')
      return true
    },
  )

  // A bare URL string under a key that says nothing about URLs is still a URL.
  await assert.rejects(
    () => guard('fetch')({ note: `https://example.test/${FIXED_CANARY}` }, exec),
    (error) => {
      assert.equal(error.where, 'url')
      return true
    },
  )

  // A URL embedded in prose is denied too, and recorded as `args`: `where` is
  // decided by the field the echo sat in, not by scraping URLs out of text.
  await assert.rejects(
    () => guard('write_file')({ note: `see https://example.test/${FIXED_CANARY}` }, exec),
    (error) => {
      assert.equal(error.code, CANARY_TRIP)
      assert.equal(error.where, 'args')
      return true
    },
  )

  assert.deepEqual(calls, [])
  assert.deepEqual(
    readIncidents(path).map((incident) => incident.where),
    ['url', 'url', 'args'],
  )
})

test('wrapExecute passes a clean call straight through, untouched', async (t) => {
  const { calls, path, guard } = harness(t)
  const args = { url: 'https://example.test/', body: NEAR_MISSES.join(' ') }

  const result = await guard('http_get')(args, exec)

  assert.deepEqual(result, { ok: true })
  assert.equal(calls.length, 1)
  // Not merely equal: this plugin redacts nothing and rewrites nothing.
  assert.equal(calls[0], args)
  assert.deepEqual(readIncidents(path), [])
  assert.deepEqual(summarizeIncidents(path), {
    incidents: 0,
    lastTool: null,
    lastAt: null,
    lastWhere: null,
  })
})

test('each denial is exactly one incident line, and the count keeps climbing', async (t) => {
  const { path, guard } = harness(t)

  for (const tool of ['alpha', 'beta', 'gamma']) {
    await assert.rejects(() => guard(tool)({ q: FIXED_CANARY }, exec))
  }

  const incidents = readIncidents(path)
  assert.equal(incidents.length, 3)
  assert.deepEqual(
    incidents.map((incident) => incident.tool),
    ['alpha', 'beta', 'gamma'],
  )
  for (const incident of incidents) {
    assert.deepEqual(Object.keys(incident).sort(), ['tool', 'ts', 'where'])
    assert.match(incident.ts, /^\d{4}-\d{2}-\d{2}T/)
  }

  const summary = summarizeIncidents(path)
  assert.equal(summary.incidents, 3)
  assert.equal(summary.lastTool, 'gamma')
  assert.equal(summary.lastWhere, 'args')
})

test('the incident log holds no trace of the canary after the plant', async (t) => {
  const { path, guard } = harness(t)

  await assert.rejects(() => guard('write_file')({ body: FIXED_CANARY }, exec))
  await assert.rejects(() => guard('http_get')({ url: `https://x.test/${FIXED_CANARY}` }, exec))

  const text = readFileSync(path, 'utf8')
  assertNoCanaryLeak(text, FIXED_CANARY, 'the incident log')
  // Not even the disclosable prefix reaches the file: the log knows that a
  // tripwire fired, not which tripwire it was.
  assert.equal(text.includes(CANARY_PREFIX), false)
  assert.equal(text.trim().split('\n').length, 2)
  for (const line of text.trim().split('\n')) {
    assert.deepEqual(Object.keys(JSON.parse(line)).sort(), ['tool', 'ts', 'where'])
  }
})

test('appendIncident writes three scalars and cannot be talked into more', async (t) => {
  const path = tempLog(t)

  const written = appendIncident(path, {
    ts: '2026-08-31T00:00:00.000Z',
    tool: 'http_get',
    where: 'url',
    // Everything below is ignored: the record is built here, not spread.
    canary: FIXED_CANARY,
    args: { body: FIXED_CANARY },
  })

  assert.deepEqual(written, {
    ts: '2026-08-31T00:00:00.000Z',
    tool: 'http_get',
    where: 'url',
  })
  assertNoCanaryLeak(readFileSync(path, 'utf8'), FIXED_CANARY, 'the incident log')

  // Missing or nonsense fields fall back rather than landing verbatim.
  const fallback = appendIncident(path, { where: 'somewhere else' })
  assert.equal(fallback.tool, 'unknown')
  assert.equal(fallback.where, 'args')
  assert.match(fallback.ts, /^\d{4}-\d{2}-\d{2}T/)
})

test('the reader drops torn and foreign lines instead of echoing them', async (t) => {
  const path = tempLog(t)
  appendIncident(path, { ts: '2026-08-31T00:00:00.000Z', tool: 'good', where: 'url' })
  appendFileSync(
    path,
    [
      'not json at all',
      JSON.stringify({ ts: '2026-08-31T00:00:01.000Z', tool: 'bad', where: 'elsewhere' }),
      JSON.stringify({ ts: 1, tool: 'bad', where: 'args' }),
      JSON.stringify({ ts: '2026-08-31T00:00:02.000Z', tool: 'sneaky', where: 'args', c: FIXED_CANARY }),
      '{"ts": "torn',
      '',
    ].join('\n'),
    'utf8',
  )

  const incidents = readIncidents(path)

  assert.deepEqual(incidents, [
    { ts: '2026-08-31T00:00:00.000Z', tool: 'good', where: 'url' },
    { ts: '2026-08-31T00:00:02.000Z', tool: 'sneaky', where: 'args' },
  ])
  // A log appended to by something else cannot smuggle a canary back out.
  assertNoCanaryLeak(incidents, FIXED_CANARY, 'readIncidents')
  assert.deepEqual(readIncidents('/nonexistent/dsh-canary/incidents.jsonl'), [])
})

test('assertNoCanary and assertNoCanaryInUrl throw and write nothing', async (t) => {
  const path = tempLog(t)
  const state = plantCanary({ canary: FIXED_CANARY, incidentLog: path }, {})

  assert.throws(
    () => assertNoCanary({ body: FIXED_CANARY }, state, { tool: 'write_file' }),
    (error) => {
      assert.ok(error instanceof CanaryTripError)
      assert.equal(error.where, 'args')
      return true
    },
  )
  assert.throws(
    () => assertNoCanaryInUrl(`https://example.test/?q=${FIXED_CANARY}`, state, { tool: 'fetch' }),
    (error) => {
      assert.equal(error.where, 'url')
      assert.equal(error.tool, 'fetch')
      return true
    },
  )

  assert.doesNotThrow(() => assertNoCanary({ body: 'nothing here' }, state, { tool: 'x' }))
  assert.doesNotThrow(() => assertNoCanaryInUrl('https://example.test/', state, { tool: 'x' }))

  // wrapExecute owns the incident, so one denial is one line whichever a host
  // reaches for: these two threw and appended nothing.
  assert.deepEqual(readIncidents(path), [])
})

test('plantCanary carries the prefix, the source, and the resolved log', (t) => {
  const path = tempLog(t)
  const state = plantCanary({ canary: FIXED_CANARY, incidentLog: path }, {})

  assert.deepEqual(state, {
    canary: FIXED_CANARY,
    prefix: FIXED_PREFIX,
    source: 'config',
    incidentLog: path,
  })
  assert.equal(canaryPrefix(state.canary).length, PREFIX_LENGTH)
  assert.equal(canaryPrefix(undefined), '')
})
