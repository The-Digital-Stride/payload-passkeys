// Usage: node scripts/use-payload-version.mjs 3.91.0   (or latest, beta)
import { execFileSync } from 'node:child_process'

const version = process.argv[2]
if (!version) throw new Error('Give a version, for example 3.91.0, latest or beta')
const packages = [
  'payload',
  '@payloadcms/next',
  '@payloadcms/ui',
  '@payloadcms/db-mongodb',
  '@payloadcms/db-postgres',
  '@payloadcms/db-sqlite',
]
execFileSync('pnpm', ['add', '-D', '--save-exact', ...packages.map((p) => `${p}@${version}`)], {
  stdio: 'inherit',
})
