/**
 * Repository hygiene, asserted rather than promised.
 *
 * Three claims are checked here. That the tree carries no machine names, mount
 * paths, or credential-variable names from wherever it was written. That the
 * shipped source opens nothing — no socket, no fetch, no subprocess — because a
 * tripwire that could phone home would be a worse liability than the exfil it
 * watches for. And that the README states the boundary of the product in plain
 * words, since the boundary is the part most easily overstated.
 *
 * The forbidden literals are assembled from fragments so that this file does
 * not itself trip the scan it performs.
 */
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { extname, join, relative, sep } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { CANARY_PATTERN } from '../src/canary.js'

/** The package root, walked below. */
const ROOT = fileURLToPath(new URL('..', import.meta.url))

/** Directories never worth scanning: not ours, or not text. */
const SKIP_DIRS = new Set(['node_modules', '.git'])

/** Extensions with no text worth scanning. */
const BINARY_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2'])

/**
 * Every checked-in text file, repo-relative.
 * @returns Paths relative to the package root, in directory order.
 */
function repoFiles() {
  return readdirSync(ROOT, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => relative(ROOT, join(entry.parentPath ?? entry.path, entry.name)))
    .filter((path) => !path.split(sep).some((segment) => SKIP_DIRS.has(segment)))
    .filter((path) => !BINARY_EXTENSIONS.has(extname(path)))
}

/**
 * Read a repo file as text.
 * @param path - A repo-relative path.
 * @returns Its contents.
 */
function readRepoFile(path) {
  return readFileSync(join(ROOT, path), 'utf8')
}

/**
 * The literals that must not appear anywhere in the tree, each built from
 * fragments so this file is not its own counterexample.
 */
const FORBIDDEN = [
  { what: 'a private machine name', pattern: new RegExp(['def', 'iant'].join(''), 'i') },
  { what: 'a host-local mount path', pattern: /\/mnt\/[a-z]/i },
  { what: 'a CI token variable', pattern: new RegExp(['GITHUB', 'TOKEN'].join('_')) },
  { what: 'a provider key variable', pattern: new RegExp(['ANTHROPIC', 'API', 'KEY'].join('_')) },
  { what: 'a provider key variable', pattern: new RegExp(['OPENAI', 'API', 'KEY'].join('_')) },
  { what: 'a bearer token literal', pattern: /\bBearer [A-Za-z0-9._-]{20,}/ },
]

test('the tree carries no machine names, mount paths, or credential variables', () => {
  const offences = []

  for (const path of repoFiles()) {
    const text = readRepoFile(path)
    for (const { what, pattern } of FORBIDDEN) {
      const hit = pattern.exec(text)
      if (hit !== null) offences.push(`${path}: ${what} (${hit[0].slice(0, 24)})`)
    }
  }

  assert.deepEqual(offences, [])
})

test('no committed file holds a whole canary as a contiguous literal', () => {
  // The suite's fixed plant is assembled from fragments at runtime, and the
  // README writes the shape with an ellipsis. A canary written down whole in
  // the repository would be a canary every reader of the repository holds.
  const scanner = new RegExp(CANARY_PATTERN.source.replace(/^\^|\$$/g, ''), 'g')
  const offences = []

  for (const path of repoFiles()) {
    const hit = new RegExp(scanner.source, 'g').exec(readRepoFile(path))
    if (hit !== null) offences.push(`${path}: ${hit[0].slice(0, 14)}…`)
  }

  assert.deepEqual(offences, [])
})

test('the scan actually covers the files it claims to', () => {
  const files = repoFiles()

  for (const expected of [
    'package.json',
    'package-lock.json',
    'cordis.patch.yml',
    'README.md',
    'LICENSE',
    '.gitignore',
    join('.github', 'workflows', 'ci.yml'),
    join('src', 'index.js'),
    join('src', 'canary.js'),
    join('test', 'helpers.js'),
    join('test', 'canary.test.js'),
    join('test', 'plugin.test.js'),
  ]) {
    assert.ok(files.includes(expected), `hygiene scan missed ${expected}`)
  }
  assert.equal(
    files.some((path) => path.startsWith('node_modules')),
    false,
  )
})

test('the shipped source opens nothing: no socket, no fetch, no subprocess', () => {
  // This package hashes nothing, fetches nothing, and spawns nothing. It reads
  // and appends one local file and walks strings in memory. Those are the ways
  // it could acquire an egress path of its own — including one that shipped the
  // canary somewhere off the box, which would be the exact failure this plugin
  // exists to detect in someone else.
  const banned = [
    /\bfetch\s*\(/,
    /\bXMLHttpRequest\b/,
    /\bnode:(dns|net|tls|http|https|dgram|child_process|worker_threads)\b/,
    /\brequire\s*\(/,
    /\bimport\s*\(/,
  ]

  for (const path of repoFiles().filter((file) => file.startsWith(`src${sep}`))) {
    const text = readRepoFile(path)
    for (const pattern of banned) {
      assert.equal(pattern.test(text), false, `${path} matches ${pattern}`)
    }
  }
})

test('the shipped source imports only the pinned tools package, node builtins it needs, and itself', () => {
  const allowed = new Set(['@deepseek-ai/dsh-tools', 'node:crypto', 'node:fs'])
  const specifiers = []

  for (const path of repoFiles().filter((file) => file.startsWith(`src${sep}`))) {
    const text = readRepoFile(path)
    for (const match of text.matchAll(/^\s*(?:import|export)[^'"\n]*from\s*'([^']+)'/gm)) {
      specifiers.push(match[1])
    }
  }

  assert.ok(specifiers.length > 0)
  for (const specifier of specifiers) {
    assert.ok(allowed.has(specifier) || specifier.startsWith('./'), `unexpected import ${specifier}`)
  }
})

test('CI needs no credentials', () => {
  const workflow = readRepoFile(join('.github', 'workflows', 'ci.yml'))

  assert.match(workflow, /contents: read/)
  assert.match(workflow, /npm ci/)
  assert.match(workflow, /npm test/)
  assert.match(workflow, /'22\.x', '24\.x'/)
  assert.equal(/secrets\./.test(workflow), false)
})

test('the incident log is ignored rather than committed', () => {
  const ignored = readRepoFile('.gitignore')

  for (const entry of ['node_modules/', '.env', '.dsh-canary.jsonl']) {
    assert.ok(ignored.includes(entry), `.gitignore omits ${entry}`)
  }
})

test('the README states the boundary of the product, not just its behaviour', () => {
  const readme = readRepoFile('README.md')

  // The three load-bearing claims. Overstating any of them would make this a
  // detector it is not.
  assert.match(readme, /echo-exfil of this planted canary/i)
  assert.match(readme, /not detect prompt injection in general|not a prompt-injection detector/i)
  assert.match(readme, /not a red-team product/i)

  // And the things a reader has to be able to find.
  assert.match(readme, /dsh plugin --profile default add github:jwilson411\/dsh-canary/)
  assert.match(readme, /0\.1\.1-rc\.2/)
  assert.match(readme, /CANARY_TRIP/)
  assert.match(readme, /wrapExecute/)
  assert.match(readme, /canary_context/)
  assert.match(readme, /canary_status/)
  assert.match(readme, /2026-08-31/)
})
