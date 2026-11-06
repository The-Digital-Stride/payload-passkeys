// The publish step of the release workflow (`pnpm release` runs `pnpm build` first).
//
// Publishes with `npm publish`, because npm documents OIDC trusted publishing for npm only. It
// publishes the tarball `pnpm pack` makes, never the repo directory: only pnpm applies
// publishConfig's exports, main and types, so `npm publish` run in the repo would ship a manifest
// pointing at src/. The tarball is checked first (scripts/check-package.mjs).
//
// changesets/action runs this on every push to main that has no pending changesets, so it is a
// no-op when the version is already on npm.
//
// Usage: node scripts/publish.mjs [--dry-run]   (--dry-run publishes nothing and creates no tags)
import { execFileSync } from 'node:child_process'
import { appendFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { packAndCheck } from './check-package.mjs'

const dryRun = process.argv.includes('--dry-run')
const { name, version } = JSON.parse(readFileSync('package.json', 'utf8'))

const isPublished = () => {
  try {
    const out = execFileSync('npm', ['view', `${name}@${version}`, 'version', '--json'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim()
    // An unknown version of a known package prints nothing.
    return out !== '' && JSON.parse(out) === version
  } catch (error) {
    // E404: the package itself is not on npm yet. Anything else (network, auth) stops the run.
    if (/E404/.test(String(error?.stderr ?? ''))) return false
    throw error
  }
}

if (isPublished()) {
  console.log(`${name}@${version} is already on npm; nothing to publish.`)
  // changesets/action warns when its output file is missing; an empty one means "no releases".
  if (process.env.CHANGESETS_OUTPUT) appendFileSync(process.env.CHANGESETS_OUTPUT, '')
  process.exit(0)
}

const dir = mkdtempSync(path.join(tmpdir(), 'payload-passkeys-publish-'))
try {
  const tarball = packAndCheck(dir)
  const tag = version.includes('-') ? 'next' : 'latest'
  // --provenance outside a dry run: provenance is required (design §10), so a publish that
  // cannot attest it (anywhere but the release workflow) fails instead of shipping without it.
  const flags = dryRun ? ['--dry-run'] : ['--provenance']
  execFileSync('npm', ['publish', tarball, '--access', 'public', '--tag', tag, ...flags], {
    stdio: 'inherit',
  })
  // Writes git-tag events to $CHANGESETS_OUTPUT, which changesets/action reads to push the tag
  // and create the GitHub release.
  if (!dryRun) execFileSync('pnpm', ['changeset', 'tag'], { stdio: 'inherit' })
} finally {
  rmSync(dir, { force: true, recursive: true })
}
