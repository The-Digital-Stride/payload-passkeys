import { existsSync, readFileSync, statSync } from 'fs'
import path from 'path'

export type FoundImport = { specifier: string; typeOnly: boolean }

const STATIC = /(?:^|[\s;])(import|export)\s+(type\s+)?(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]/g
const DYNAMIC = /import\(\s*['"]([^'"]+)['"]\s*\)/g

/** Lists the module specifiers in a source file, in order, marking `import type` / `export type`. */
export const scanImports = (source: string): FoundImport[] => {
  const found: { index: number; value: FoundImport }[] = []
  for (const match of source.matchAll(STATIC)) {
    const [, , typeKeyword, specifier] = match
    if (specifier)
      found.push({ index: match.index, value: { specifier, typeOnly: Boolean(typeKeyword) } })
  }
  for (const match of source.matchAll(DYNAMIC)) {
    if (match[1])
      found.push({ index: match.index, value: { specifier: match[1], typeOnly: false } })
  }
  return found.sort((a, b) => a.index - b.index).map((entry) => entry.value)
}

const resolveRelative = (from: string, specifier: string): null | string => {
  const base = path.resolve(path.dirname(from), specifier)
  const candidates = [
    base.replace(/\.js$/, '.ts'),
    base.replace(/\.js$/, '.tsx'),
    base,
    path.join(base, 'index.ts'),
    path.join(base, 'index.tsx'),
  ]
  return (
    candidates.find((candidate) => existsSync(candidate) && statSync(candidate).isFile()) ?? null
  )
}

/** Walks the runtime import graph from an entry file. */
export const walkClientGraph = (entry: string): { bare: Set<string>; files: string[] } => {
  const seen = new Set<string>()
  const bare = new Set<string>()
  const queue = [entry]
  while (queue.length) {
    const file = queue.shift()!
    if (seen.has(file)) continue
    seen.add(file)
    for (const { specifier, typeOnly } of scanImports(readFileSync(file, 'utf8'))) {
      if (typeOnly) continue
      if (specifier.startsWith('.')) {
        if (/\.(css|scss|svg|json)$/.test(specifier)) continue
        const resolved = resolveRelative(file, specifier)
        if (!resolved) throw new Error(`Cannot resolve ${specifier} from ${file}`)
        queue.push(resolved)
      } else {
        bare.add(specifier)
      }
    }
  }
  return { bare, files: [...seen] }
}
