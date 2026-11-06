import type { Config, Payload } from 'payload'

import { execFile } from 'child_process'
import { randomBytes } from 'crypto'
import { getPayload } from 'payload'
import { promisify } from 'util'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { passkeysPlugin } from '../../src/index.js'
import { resetPasskeys } from '../../src/server/reset.js'
import config from '../configs/single.js'
import { passwordClient } from '../helpers/ceremonies.js'
import { insertPasskey } from '../helpers/passkeys.js'
import { createUser, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

describe('resetPasskeys', () => {
  it('removes every passkey and every session of one user only', async () => {
    const alice = await createUser(payload, 'users')
    const bob = await createUser(payload, 'users')
    await insertPasskey(payload, { collection: 'users', userId: alice.id })
    await insertPasskey(payload, { collection: 'users', userId: alice.id })
    await insertPasskey(payload, { collection: 'users', userId: bob.id })
    const pending = (userId: number | string) => ({
      authCollection: 'users',
      browserKeyHash: 'x',
      challenge: randomBytes(32).toString('base64url'),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      type: 'registration',
      userId: String(userId),
    })
    await payload.create({ collection: 'passkey-challenges', data: pending(alice.id) } as never)
    await payload.create({ collection: 'passkey-challenges', data: pending(bob.id) } as never)
    const signedIn = await passwordClient(config, 'users', alice.email)

    const result = await resetPasskeys({
      collection: 'users',
      email: alice.email.toUpperCase(),
      payload,
    })
    expect(result).toEqual({ removedPasskeys: 2, removedSessions: 1, userId: alice.id })
    expect((await signedIn.get('/api/users/me')).json.user).toBeNull()
    expect((await rawUser(payload, 'users', alice.id)).sessions ?? []).toHaveLength(0)
    expect(
      (await payload.count({ collection: 'passkeys', where: { user: { equals: bob.id } } }))
        .totalDocs,
    ).toBe(1)
    const challengesOf = async (userId: number | string) =>
      (
        await payload.count({
          collection: 'passkey-challenges',
          where: { userId: { equals: String(userId) } },
        } as never)
      ).totalDocs
    expect(await challengesOf(alice.id)).toBe(0)
    expect(await challengesOf(bob.id)).toBe(1)
  })

  it('refuses an unknown user or collection', async () => {
    await expect(
      resetPasskeys({ collection: 'users', email: 'nobody@example.test', payload }),
    ).rejects.toThrow(/No users user/)
    await expect(
      resetPasskeys({ collection: 'posts', email: 'x@example.test', payload }),
    ).rejects.toThrow(/not a passkeys collection/)
  })

  it('is registered as a Payload bin script', async () => {
    const entry = (await config).bin?.find((b) => b.key === 'passkeys:reset')
    expect(entry?.scriptPath).toMatch(/[/\\]bin[/\\]reset\.(ts|js)$/)
  })

  it('is registered even when the plugin is disabled, so recovery always works', () => {
    const host = {
      bin: [{ key: 'other', scriptPath: '/x.js' }],
      collections: [{ slug: 'users', auth: true, fields: [] }],
      secret: 'x',
      serverURL: 'https://example.com',
    } as unknown as Config
    const keys = passkeysPlugin({ enabled: false })(host).bin?.map((b) => b.key)
    expect(keys).toEqual(['other', 'passkeys:reset'])
  })
})

// The spawned CLI reaches the same database through DATABASE_URL and DATABASE_ADAPTER (inherited),
// must not drop it, and must not leave a generate:types child behind (VITEST turns that off).
const runCli = (args: string[]) =>
  promisify(execFile)('pnpm', ['dev:payload', 'passkeys:reset', ...args], {
    env: { ...process.env, PAYLOAD_DROP_DATABASE: 'false', VITEST: '1' },
    timeout: 90_000,
  })

describe('the CLI', () => {
  it('runs through `payload passkeys:reset`', async () => {
    const alice = await createUser(payload, 'users')
    await insertPasskey(payload, { collection: 'users', userId: alice.id })
    const { stdout } = await runCli(['--collection', 'users', '--email', alice.email])
    expect(stdout).toMatch(/Removed 1 passkey and signed out 0 sessions/)
    expect(
      (await payload.count({ collection: 'passkeys', where: { user: { equals: alice.id } } }))
        .totalDocs,
    ).toBe(0)
  }, 120_000)

  it('exits non-zero and says why when no user matches', async () => {
    const failure = await runCli(['--collection', 'users', '--email', 'nobody@example.test']).catch(
      (error: { code?: number; stderr?: string }) => error,
    )
    expect(failure).toMatchObject({
      code: 1,
      stderr: expect.stringMatching(/No users user matches/),
    })
  }, 120_000)
})
