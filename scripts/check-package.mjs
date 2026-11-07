// Packs the package as it will be published (pnpm applies publishConfig, so the packed manifest's
// exports point at dist/), checks what is inside, then runs publint and attw on that same tarball.
// Run after `pnpm build`: `pnpm check:package` does both. What is checked is exactly what is
// published: scripts/publish.mjs publishes the tarball packAndCheck returns, and the release
// workflow checks the tarball it packed and then publishes that file.
//
// Usage: node scripts/check-package.mjs [tarball]   (packs dist/ first when no tarball is given)
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const run = (command, args, options = {}) =>
  execFileSync(command, args, { stdio: 'inherit', ...options })

/**
 * Throws, listing every problem, unless the tarball's files and manifest are fit to publish. Needs
 * nothing but `tar`, so the release workflow's publish job, which installs no dependencies, can
 * run it too.
 */
export const checkTarballContents = (tarball) => {
  const dir = mkdtempSync(path.join(tmpdir(), 'payload-passkeys-check-'))
  try {
    run('tar', ['-xzf', tarball, '-C', dir])
    const root = path.join(dir, 'package')
    const manifest = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'))
    const files = execFileSync('find', ['.', '-type', 'f'], { cwd: root })
      .toString()
      .split('\n')
      .filter(Boolean)
    const has = (file) => files.includes(`./${file.replace(/^\.\//, '')}`)

    const problems = []
    if (!manifest.exports || typeof manifest.exports !== 'object') problems.push('no exports map')
    for (const [entry, target] of Object.entries(manifest.exports ?? {})) {
      for (const [condition, file] of Object.entries(target)) {
        if (!file.startsWith('./dist/'))
          problems.push(`${entry} ${condition} is outside dist: ${file}`)
        if (!has(file)) problems.push(`${entry} ${condition} points at missing ${file}`)
      }
      if (!target.types) problems.push(`${entry} has no types condition`)
    }
    for (const field of ['main', 'types']) {
      if (!manifest[field] || !has(manifest[field]))
        problems.push(`${field} points at missing ${manifest[field]}`)
    }
    for (const file of files) {
      if (/^\.\/(src|test|dev|docs|scripts|\.github)\//.test(file))
        problems.push(`unexpected file ${file}`)
      if (/\.(spec|test)\.[cm]?[jt]sx?$/.test(file)) problems.push(`test file ${file}`)
      if (/\.tsbuildinfo$|(^|\/)\.env/.test(file)) problems.push(`unexpected file ${file}`)
    }
    if (!has('dist/bin/reset.js')) problems.push('the passkeys:reset script is missing')
    if (!has('dist/components/passkeys.css')) problems.push('passkeys.css is missing')
    // A stale tsbuildinfo once made tsc emit nothing, and the tarball shipped without types.
    if (!has('dist/index.d.ts')) problems.push('dist/index.d.ts is missing')
    if (!files.some((file) => file.endsWith('.d.ts'))) problems.push('no type declarations')
    for (const [name, range] of Object.entries(manifest.dependencies ?? {})) {
      if (!/^\d+\.\d+\.\d+$/.test(range))
        problems.push(`dependency ${name} is not pinned exactly: ${range}`)
    }
    if (manifest.dependencies?.['@simplewebauthn/server'] !== '14.0.3') {
      problems.push('SimpleWebAuthn server is not pinned to 14.0.3')
    }
    if (problems.length) throw new Error(`Package problems:\n${problems.join('\n')}`)
    console.log(
      `Package OK: ${files.length} files, exports ${Object.keys(manifest.exports).join(', ')}`,
    )
  } finally {
    rmSync(dir, { force: true, recursive: true })
  }
}

/** checkTarballContents, then publint and attw. Throws unless the tarball is fit to publish. */
export const checkTarball = (tarball) => {
  checkTarballContents(tarball)
  // Both read the tarball pnpm made, not the repo: in the repo, `exports` points at src/.
  run('pnpm', ['exec', 'publint', 'run', tarball, '--strict'])
  run('pnpm', ['exec', 'attw', tarball, '--profile', 'esm-only'])
}

/** Packs the built package into `destination`, checks it and returns the tarball's path. */
export const packAndCheck = (destination) => {
  run('pnpm', ['pack', '--pack-destination', destination], {
    stdio: ['ignore', 'ignore', 'inherit'],
  })
  const tarballs = readdirSync(destination).filter((file) => file.endsWith('.tgz'))
  if (tarballs.length !== 1) throw new Error(`expected one tarball, found ${tarballs.join(', ')}`)
  const tarball = path.join(destination, tarballs[0])
  checkTarball(tarball)
  return tarball
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const given = process.argv[2]
  const dir = given ? undefined : mkdtempSync(path.join(tmpdir(), 'payload-passkeys-pack-'))
  try {
    if (given) checkTarball(path.resolve(given))
    else packAndCheck(dir)
  } catch (error) {
    // The failing tool has already printed its findings.
    console.error(error instanceof Error ? error.message : error)
    process.exitCode = 1
  } finally {
    if (dir) rmSync(dir, { force: true, recursive: true })
  }
}
