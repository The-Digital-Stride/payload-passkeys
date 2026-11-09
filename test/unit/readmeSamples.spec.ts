import { readFileSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { describe, expect, it } from 'vitest'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const readme = readFileSync(path.join(root, 'README.md'), 'utf8')
const samples = readFileSync(path.join(root, 'dev/readme-samples.ts'), 'utf8')

/** Each `// readme:<name>` … `// readme:end` region of dev/readme-samples.ts. */
const regions = [...samples.matchAll(/^\/\/ readme:([\w-]+)\n([\s\S]*?)^\/\/ readme:end$/gm)].map(
  ([, name, body]) => ({ body: body!.trimEnd(), name: name! }),
)

/** The README's TypeScript code blocks. */
const blocks = [...readme.matchAll(/^```ts\n([\s\S]*?)^```$/gm)].map(([, body]) => body!.trimEnd())

describe('README code samples', () => {
  it('finds the regions', () => {
    expect(regions.map((r) => r.name)).toEqual([
      'minimal',
      'options',
      'csrf',
      'vercel',
      'upstash',
      'on-sign-in',
      'translations',
      'sso-option',
      'sso-callback',
      'sso-offboarding',
      'sso-wording',
    ])
  })

  it.each(regions)('shows the type-checked $name sample verbatim', ({ body }) => {
    expect(blocks).toContain(body)
  })

  it('has no TypeScript block that is not type-checked', () => {
    const checked = new Set(regions.map((r) => r.body))
    expect(blocks.filter((block) => !checked.has(block))).toEqual([])
  })
})
