import path from 'path'
import { describe, expect, it } from 'vitest'

import { scanImports, walkClientGraph } from '../helpers/importGraph.js'

const root = path.resolve(import.meta.dirname, '../..')

/** Every bare import a client or RSC entry may make at runtime (type imports are free). */
const ALLOWED_BARE = new Set([
  '@payloadcms/ui',
  '@simplewebauthn/browser',
  'next/navigation.js',
  'payload/shared',
  'react',
  'react/jsx-runtime',
])

describe('scanImports', () => {
  it('finds value imports and skips type-only ones', () => {
    const found = scanImports(
      [
        `import type { A } from 'payload'`,
        `export type { B } from './b.js'`,
        `import { type C, d } from './d.js'`,
        `import React, {\n  useState,\n} from 'react'`,
        `import './side-effect.css'`,
        `export { e } from '../server/e.js'`,
        `const lazy = await import('@simplewebauthn/server')`,
      ].join('\n'),
    )
    expect(found.filter((f) => !f.typeOnly).map((f) => f.specifier)).toEqual([
      './d.js',
      'react',
      './side-effect.css',
      '../server/e.js',
      '@simplewebauthn/server',
    ])
    expect(found.filter((f) => f.typeOnly).map((f) => f.specifier)).toEqual(['payload', './b.js'])
  })
})

describe.each(['src/exports/client.ts', 'src/exports/rsc.ts'])('%s', (entry) => {
  const graph = walkClientGraph(path.join(root, entry))

  it('reaches no server module', () => {
    const forbidden = graph.files.filter((file) =>
      /[/\\]src[/\\](server|collections|bin|translations)[/\\]|[/\\]src[/\\]index\.ts$/.test(file),
    )
    expect(forbidden).toEqual([])
  })

  it('imports only the allowed packages at runtime', () => {
    const disallowed = [...graph.bare].filter((specifier) => !ALLOWED_BARE.has(specifier))
    expect(disallowed).toEqual([])
  })
})
