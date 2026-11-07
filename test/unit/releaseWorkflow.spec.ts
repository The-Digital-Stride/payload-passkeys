import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { parse } from 'yaml'

// The release workflow's shape is a security property: the job that holds the npm OIDC token must
// never run the repository's dependencies, their install scripts or a restored cache.

type Step = {
  env?: Record<string, string>
  run?: string
  uses?: string
  with?: Record<string, unknown>
}
type Job = {
  environment?: string
  needs?: string | string[]
  permissions?: Record<string, string>
  steps: Step[]
  'timeout-minutes'?: number
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const read = (file: string) => parse(readFileSync(path.join(root, file), 'utf8'))
const workflow = read('.github/workflows/release.yml') as {
  jobs: Record<string, Job>
  permissions: unknown
}
const jobs = Object.entries(workflow.jobs)
const setupAction = read('.github/actions/setup/action.yml') as { runs: { steps: Step[] } }

const PINNED = /^[\w.-]+\/[\w.-]+(\/[\w./-]+)?@[0-9a-f]{40}$/

/** True when the step installs or runs the repository's dependencies or restores a cache. */
const touchesDependencies = (step: Step): boolean =>
  step.uses === './.github/actions/setup' ||
  /\bpnpm\b|\bnpx\b|\byarn\b|npm (ci|install|i|exec|run|test)\b(?! -g npm@)/.test(step.run ?? '') ||
  /\/cache@|pnpm\/action-setup@/.test(step.uses ?? '') ||
  (step.with?.cache !== undefined && step.with.cache !== '')

describe('release workflow', () => {
  it('grants nothing at the top level', () => {
    expect(workflow.permissions).toEqual({})
  })

  it('gives the OIDC token to exactly one job, behind the release environment', () => {
    const withToken = jobs.filter(([, job]) => job.permissions?.['id-token'] === 'write')
    expect(withToken.map(([name]) => name)).toEqual(['publish'])
    expect(withToken[0]?.[1].environment).toBe('release')
  })

  it('installs, builds and restores no cache in the job holding the OIDC token', () => {
    const [, publish] = jobs.find(([name]) => name === 'publish')!
    expect(publish.steps.filter(touchesDependencies)).toEqual([])
    const setupNode = publish.steps.find((step) => step.uses?.startsWith('actions/setup-node@'))
    expect(setupNode?.with?.['package-manager-cache']).toBe(false)
  })

  it('restores no cache and holds no OIDC token wherever it installs dependencies', () => {
    for (const [name, job] of jobs) {
      for (const step of job.steps) {
        if (step.uses === './.github/actions/setup') {
          expect(step.with?.cache, `${name} restores a cache`).toBe('')
          expect(job.permissions?.['id-token'], `${name} has id-token`).toBeUndefined()
        }
      }
    }
  })

  it('builds the tarball in a read-only job and publishes that artifact', () => {
    const { build, publish } = workflow.jobs
    expect(build?.permissions).toEqual({ contents: 'read' })
    expect(build?.steps.some((step) => step.uses?.startsWith('actions/upload-artifact@'))).toBe(
      true,
    )
    expect(publish?.needs).toBe('build')
    expect(publish?.steps.some((step) => step.uses?.startsWith('actions/download-artifact@'))).toBe(
      true,
    )
  })

  it('pins every action to a commit, persists no credentials and sets a timeout', () => {
    for (const [name, job] of jobs) {
      expect(job['timeout-minutes'], `${name} timeout`).toBeGreaterThan(0)
      for (const step of [...job.steps, ...setupAction.runs.steps]) {
        if (!step.uses || step.uses.startsWith('./')) continue
        expect(step.uses, `${name}: ${step.uses}`).toMatch(PINNED)
        if (step.uses.startsWith('actions/checkout@')) {
          expect(step.with?.['persist-credentials'], `${name} checkout`).toBe(false)
        }
      }
    }
  })
})
