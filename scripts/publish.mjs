// Publishes the package with `npm publish`, because npm documents OIDC trusted publishing for npm
// only. It always publishes a tarball `pnpm pack` made, never the repo directory: only pnpm applies
// publishConfig's exports, main and types, so `npm publish` run in the repo would ship a manifest
// pointing at src/ (package.json's prepublishOnly refuses that).
//
// The release workflow (.github/workflows/release.yml) builds, packs and checks the tarball in a
// job with no publishing rights, then a separate job with the npm OIDC token and no dependencies
// installed publishes that exact file:
//
//   node scripts/publish.mjs --tarball <file> --check   writes needed, version and dist-tag to
//                                                       $GITHUB_OUTPUT; publishes nothing
//   node scripts/publish.mjs --tarball <file>           publishes that tarball
//   node scripts/publish.mjs                            `pnpm release`: packs dist/, checks the
//                                                       tarball (scripts/check-package.mjs) and
//                                                       publishes it
//
// Add --dry-run to publish nothing. Every mode is a no-op when the version is already on npm, so a
// re-run of the workflow is safe.
import { execFileSync } from 'node:child_process'
import { appendFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { checkTarballContents, packAndCheck } from './check-package.mjs'

const args = process.argv.slice(2)
const dryRun = args.includes('--dry-run')
const checkOnly = args.includes('--check')
const tarballIndex = args.indexOf('--tarball')
const givenTarball = tarballIndex === -1 ? undefined : args[tarballIndex + 1]
if (tarballIndex !== -1 && (!givenTarball || givenTarball.startsWith('--'))) {
  throw new Error('--tarball needs the path of a .tgz file')
}
if (checkOnly && !givenTarball) throw new Error('--check needs --tarball <file>')

/** The manifest inside a packed tarball: what npm will publish, not the repo's package.json. */
const readPackedManifest = (tarball) =>
  JSON.parse(execFileSync('tar', ['-xzOf', tarball, 'package/package.json'], { encoding: 'utf8' }))

const isPublished = (name, version) => {
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

// package.json holds 0.0.0 until the first version PR is merged: never publish it.
const UNRELEASED = '0.0.0'

const distTag = (version) => (version.includes('-') ? 'next' : 'latest')

const publish = (tarball, { name, version }) => {
  // --provenance outside a dry run: provenance is required (design §10), so a publish that cannot
  // attest it (anywhere but the release workflow) fails instead of shipping without it.
  const flags = dryRun ? ['--dry-run'] : ['--provenance']
  execFileSync(
    'npm',
    ['publish', tarball, '--access', 'public', '--tag', distTag(version), ...flags],
    { stdio: 'inherit' },
  )
  console.log(`${dryRun ? 'Dry run: would have published' : 'Published'} ${name}@${version}.`)
}

if (givenTarball) {
  const tarball = path.resolve(givenTarball)
  // The structural checks need no dependencies, so the publish job repeats them on the file it
  // downloaded. publint and attw ran in the build job (scripts/check-package.mjs).
  checkTarballContents(tarball)
  const manifest = readPackedManifest(tarball)
  const unreleased = manifest.version === UNRELEASED
  const needed = !unreleased && !isPublished(manifest.name, manifest.version)
  if (unreleased) console.log(`${manifest.version} is the unreleased placeholder; not publishing.`)
  if (checkOnly) {
    console.log(
      `${manifest.name}@${manifest.version}: ${needed ? 'to publish' : 'nothing to publish'}.`,
    )
    if (process.env.GITHUB_OUTPUT) {
      appendFileSync(
        process.env.GITHUB_OUTPUT,
        `needed=${needed}\nversion=${manifest.version}\ndist-tag=${distTag(manifest.version)}\n`,
      )
    }
  } else if (!needed) {
    if (!unreleased) console.log(`${manifest.name}@${manifest.version} is already on npm.`)
  } else {
    publish(tarball, manifest)
  }
} else {
  const manifest = JSON.parse(readFileSync('package.json', 'utf8'))
  if (manifest.version === UNRELEASED) {
    console.log(`${manifest.version} is the unreleased placeholder; not publishing.`)
  } else if (isPublished(manifest.name, manifest.version)) {
    console.log(`${manifest.name}@${manifest.version} is already on npm; nothing to publish.`)
  } else {
    const dir = mkdtempSync(path.join(tmpdir(), 'payload-passkeys-publish-'))
    try {
      publish(packAndCheck(dir), manifest)
    } finally {
      rmSync(dir, { force: true, recursive: true })
    }
  }
}
