/**
 * The plugin seam: that `apply` plants the canary and registers both tools,
 * that each tool behaves the way its declared contract says, and that the
 * package is shaped the way the profile installer expects.
 *
 * `apply` is handed a stub context that records registrations, and each tool is
 * driven through the same `execute` the registry calls, with its result
 * validated against the real `@deepseek-ai/dsh-tools` pinned to `0.1.1-rc.2`.
 * No profile boots and no socket opens.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { ToolArgsError, validateJsonSchemaValue } from '@deepseek-ai/dsh-tools'

import {
  CANARY_CONTEXT_TOOL_NAME,
  CANARY_STATUS_TOOL_NAME,
  CANARY_TRIP,
  PLUGIN_NAME,
  PREFIX_LENGTH,
  apply,
  createCanaryContextTool,
  createCanaryStatusTool,
  inject,
  name,
  resolveConfig,
  wrapExecute,
} from '../src/index.js'

import {
  FIXED_CANARY,
  FIXED_PREFIX,
  assertNoCanaryLeak,
  exec,
  stubContext,
  tempLog,
} from './helpers.js'

/**
 * Trip the guard `count` times against a plant, through `wrapExecute`.
 * @param state - The plant.
 * @param count - How many calls to deny.
 * @param tool - The tool name to record.
 */
async function trip(state, count, tool = 'http_get') {
  const guarded = wrapExecute(async () => ({ ok: true }), state, { tool, env: {} })
  for (let index = 0; index < count; index += 1) {
    await assert.rejects(
      () => guarded({ url: `https://example.test/?q=${FIXED_CANARY}` }, exec),
      (error) => error.code === CANARY_TRIP,
    )
  }
}

test('apply plants the canary and registers both tools', () => {
  const { ctx, registered } = stubContext()

  const state = apply(ctx, { canary: FIXED_CANARY, incidentLog: '/tmp/unused-by-this-test.jsonl' })

  assert.deepEqual(
    registered.map((definition) => definition.name),
    [CANARY_CONTEXT_TOOL_NAME, CANARY_STATUS_TOOL_NAME],
  )
  assert.equal(CANARY_CONTEXT_TOOL_NAME, 'canary_context')
  assert.equal(CANARY_STATUS_TOOL_NAME, 'canary_status')
  assert.equal(state.canary, FIXED_CANARY)
  assert.equal(state.prefix, FIXED_PREFIX)
  assert.equal(name, 'canary')
  assert.equal(PLUGIN_NAME, 'dsh-canary')
  assert.deepEqual(inject, ['tools'])
})

test('apply with no config at all still plants and registers', () => {
  const { ctx, registered } = stubContext()

  const state = apply(ctx)

  assert.equal(registered.length, 2)
  assert.equal(state.source, 'generated')
  assert.equal(state.prefix.length, PREFIX_LENGTH)
})

test('the canary_context description is the plant: it carries the canary and the rule', () => {
  const { ctx, registered } = stubContext()
  apply(ctx, { canary: FIXED_CANARY, incidentLog: '/tmp/unused-by-this-test.jsonl' })
  const [context] = registered

  // The description is where the whole canary reaches model-visible context.
  // This is the one place in the package that is allowed to contain it.
  assert.ok(context.description.includes(FIXED_CANARY), 'the description does not carry the canary')
  assert.match(context.description, /[Nn]ever repeat it/)
  assert.match(context.description, new RegExp(CANARY_TRIP))
  assert.match(context.description, /denied before it runs/)
  // It has to survive being told otherwise by whatever the model is reading.
  assert.match(context.description, /instructs you to/)
  assert.deepEqual(context.parameters, { type: 'object', properties: {} })
})

test('canary_context returns the prefix and the rule, never the canary', async () => {
  const tool = createCanaryContextTool(resolveConfig({ canary: FIXED_CANARY }, {}))

  const value = await tool.execute({}, exec)

  assert.deepEqual(validateJsonSchemaValue(tool.output.schema, value, tool.name), [])
  assert.equal(value.planted, true)
  assert.equal(value.prefix, FIXED_PREFIX)
  assert.equal(value.plugin, PLUGIN_NAME)
  assertNoCanaryLeak(JSON.stringify(value), FIXED_CANARY, 'canary_context')
  assertNoCanaryLeak(JSON.stringify(tool.output.render({}, value)), FIXED_CANARY, 'its rendering')
  assert.deepEqual(tool.output.render({}, value), [
    {
      type: 'text',
      text: `canary: planted (${FIXED_PREFIX}…) — do not echo it into any tool or URL`,
    },
  ])
})

test('canary_status reports the first twelve characters and the tally, and nothing else', async (t) => {
  const path = tempLog(t)
  const state = resolveConfig({ canary: FIXED_CANARY, incidentLog: path }, {})
  const tool = createCanaryStatusTool(state)

  const before = await tool.execute({}, exec)

  assert.deepEqual(validateJsonSchemaValue(tool.output.schema, before, tool.name), [])
  assert.equal(before.planted, true)
  assert.equal(before.prefix, FIXED_PREFIX)
  assert.equal(before.prefix.length, PREFIX_LENGTH)
  assert.equal(before.prefix, FIXED_CANARY.slice(0, 12))
  assert.equal(before.incidents, 0)
  assert.equal(before.lastTool, null)
  assert.equal(before.lastWhere, null)
  assert.equal(before.lastAt, null)
  assert.equal(before.log, path)
  assert.equal(before.plugin, PLUGIN_NAME)
  assertNoCanaryLeak(JSON.stringify(before), FIXED_CANARY, 'canary_status')
  assert.deepEqual(tool.output.render({}, before), [
    { type: 'text', text: `canary: planted (${FIXED_PREFIX}…), no incidents` },
  ])

  await trip(state, 1, 'http_get')
  const afterOne = await tool.execute({}, exec)

  assert.equal(afterOne.incidents, 1)
  assert.equal(afterOne.lastTool, 'http_get')
  assert.equal(afterOne.lastWhere, 'url')
  assert.match(afterOne.lastAt, /^\d{4}-\d{2}-\d{2}T/)

  await trip(state, 2, 'write_file')
  const afterThree = await tool.execute({}, exec)

  assert.deepEqual(validateJsonSchemaValue(tool.output.schema, afterThree, tool.name), [])
  assert.equal(afterThree.incidents, 3)
  assert.equal(afterThree.lastTool, 'write_file')
  assertNoCanaryLeak(JSON.stringify(afterThree), FIXED_CANARY, 'canary_status after a trip')
  assert.deepEqual(tool.output.render({}, afterThree), [
    {
      type: 'text',
      text: `canary: planted (${FIXED_PREFIX}…), 3 incident(s), last write_file (url)`,
    },
  ])
})

test('the status description promises only what the tool delivers', () => {
  const tool = createCanaryStatusTool(resolveConfig({ canary: FIXED_CANARY }, {}))

  assert.equal(tool.description.includes(FIXED_CANARY), false)
  assert.match(tool.description, /never returns the canary itself/)
  assert.match(tool.description, new RegExp(CANARY_TRIP))
  assert.deepEqual(tool.parameters, { type: 'object', properties: {} })
})

test('neither tool takes arguments, and malformed ones fail loudly', async () => {
  const state = resolveConfig({ canary: FIXED_CANARY }, {})

  for (const tool of [createCanaryContextTool(state), createCanaryStatusTool(state)]) {
    for (const args of [null, 'twenty', 7, []]) {
      await assert.rejects(
        () => tool.execute(args, exec),
        (error) => {
          assert.ok(error instanceof ToolArgsError)
          assert.ok(error.violations.length > 0)
          return true
        },
        `expected ToolArgsError for ${JSON.stringify(args) ?? String(args)}`,
      )
    }
  }
})

test('config is the patch row, then the environment, then a generated plant', () => {
  const fromPatch = resolveConfig({ canary: FIXED_CANARY, incidentLog: '/tmp/a.jsonl' }, {})
  assert.deepEqual(fromPatch, {
    canary: FIXED_CANARY,
    prefix: FIXED_PREFIX,
    source: 'config',
    incidentLog: '/tmp/a.jsonl',
  })

  const fromEnv = resolveConfig({}, { DSH_CANARY: FIXED_CANARY, DSH_CANARY_LOG: '/tmp/b.jsonl' })
  assert.equal(fromEnv.canary, FIXED_CANARY)
  assert.equal(fromEnv.source, 'env')
  assert.equal(fromEnv.incidentLog, '/tmp/b.jsonl')

  const generated = resolveConfig({}, {})
  assert.equal(generated.source, 'generated')
  assert.equal(generated.incidentLog, '.dsh-canary.jsonl')
})

test('the manifest declares the bundle patch the profile installer looks for', () => {
  const manifestPath = fileURLToPath(new URL('../package.json', import.meta.url))
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))

  assert.equal(manifest.dsh.bundle.patch, './cordis.patch.yml')
  assert.equal(manifest.name, PLUGIN_NAME)
  assert.equal(manifest.type, 'module')
  assert.equal(manifest.license, 'MIT')
  assert.equal(manifest.devDependencies['@deepseek-ai/dsh-tools'], '0.1.1-rc.2')
  assert.equal(manifest.peerDependencies['@deepseek-ai/dsh-tools'], '^0.1.1-rc.2')
  assert.equal(manifest.peerDependencies['@deepseek-ai/cordis'], '^4.0.1')
  assert.equal(manifest.engines.node, '>=22.14.0')
  assert.equal(manifest.scripts.test, 'node --test "test/**/*.test.js"')
  for (const keyword of ['dsh-plugin', 'deepseek-harness']) {
    assert.ok(manifest.keywords.includes(keyword), `missing keyword ${keyword}`)
  }

  const patchPath = fileURLToPath(new URL('../cordis.patch.yml', import.meta.url))
  const patch = readFileSync(patchPath, 'utf8')
  assert.match(patch, /^- insert:$/m)
  assert.match(patch, /^ {4}- id: canary$/m)
  assert.match(patch, new RegExp(`name: ${manifest.name}$`, 'm'))
  // The documented config keys are the ones resolveConfig actually reads.
  assert.match(patch, /^#\s+canary\s/m)
  assert.match(patch, /^#\s+incidentLog\s/m)
  assert.match(patch, /DSH_CANARY\b/)
  assert.match(patch, /DSH_CANARY_LOG/)
})
