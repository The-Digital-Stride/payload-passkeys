import type { Config, Payload, PayloadRequest } from 'payload'

import { execFile } from 'child_process'
import { randomBytes } from 'crypto'
import { getPayload } from 'payload'
import { promisify } from 'util'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

import { passkeysPlugin, resetPasskeys } from '../../src/index.js'
import { isWriteConflict } from '../../src/server/sessions.js'
import config from '../configs/single.js'
import { passwordClient } from '../helpers/ceremonies.js'
import { insertPasskey } from '../helpers/passkeys.js'
import { missingUserId } from '../helpers/requests.js'
import { createUser, interceptSessionWrites, rawUser } from '../helpers/users.js'

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
    ).rejects.toThrow('No user in the users collection matches nobody@example.test.')
    await expect(
      resetPasskeys({ collection: 'posts', email: 'x@example.test', payload }),
    ).rejects.toThrow(/not a passkeys collection/)
  })

  it('names the collection when no user matches', async () => {
    await expect(
      resetPasskeys({ collection: 'users', email: 'nobody@example.com', payload }),
    ).rejects.toThrow('No user in the users collection matches nobody@example.com.')
    await expect(
      resetPasskeys({ collection: 'users', id: String(missingUserId()), payload }),
    ).rejects.toThrow(`No user in the users collection matches id ${missingUserId()}.`)
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

const adapter = process.env.DATABASE_ADAPTER ?? 'mongo'

type HookArgs = {
  doc?: Record<string, unknown>
  originalDoc?: Record<string, unknown>
  previousDoc?: Record<string, unknown>
  req: PayloadRequest
}
type Hook = (args: HookArgs) => unknown

/** Runs `run` with `hook` added to the users collection's hooks, as a host's own hook would be. */
const withUsersHooks = async <T>(
  added: { afterChange?: Hook[]; beforeChange?: Hook[] },
  run: () => Promise<T>,
): Promise<T> => {
  const hooks = payload.collections.users!.config.hooks as unknown as Record<string, Hook[]>
  const entries = Object.entries(added) as [string, Hook[]][]
  for (const [kind, list] of entries) hooks[kind] = [...(hooks[kind] ?? []), ...list]
  try {
    return await run()
  } finally {
    for (const [kind, list] of entries) hooks[kind] = hooks[kind]!.filter((h) => !list.includes(h))
  }
}

const offboard = async (userId: number | string, hooks: Parameters<typeof withUsersHooks>[0]) =>
  withUsersHooks(hooks, () =>
    payload.update({ collection: 'users', data: { name: 'Left' }, id: userId } as never),
  )

const setUpLeaver = async () => {
  const user = await createUser(payload, 'users')
  await insertPasskey(payload, { collection: 'users', userId: user.id })
  await insertPasskey(payload, { collection: 'users', userId: user.id })
  const signedIn = await passwordClient(config, 'users', user.email)
  return { signedIn, user }
}

const passkeysOf = async (userId: number | string) =>
  (await payload.count({ collection: 'passkeys', where: { user: { equals: userId } } })).totalDocs

describe('resetPasskeys from a host hook (offboarding)', () => {
  it('removes passkeys and sessions inside the hook and commits with the save', async () => {
    const { signedIn, user } = await setUpLeaver()
    let result: Awaited<ReturnType<typeof resetPasskeys>> | undefined
    await offboard(user.id, {
      afterChange: [
        async ({ doc, req }) => {
          result = await resetPasskeys({
            collection: 'users',
            id: doc!.id as number | string,
            payload: req.payload,
            req,
          })
        },
      ],
    })
    expect(result).toEqual({ removedPasskeys: 2, removedSessions: 1, userId: user.id })
    expect(await passkeysOf(user.id)).toBe(0)
    expect((await rawUser(payload, 'users', user.id)).sessions ?? []).toHaveLength(0)
    expect((await signedIn.get('/api/users/me')).json.user).toBeNull()
    expect((await rawUser(payload, 'users', user.id)).name).toBe('Left')
  })

  // SQLite runs without transactions by default, so there is nothing to roll back there.
  it.skipIf(adapter === 'sqlite')('rolls back with the save when a later hook fails', async () => {
    const { signedIn, user } = await setUpLeaver()
    let joined: unknown
    const failed = await offboard(user.id, {
      afterChange: [
        async ({ doc, req }) => {
          joined = await req.transactionID
          await resetPasskeys({
            collection: 'users',
            id: doc!.id as number | string,
            payload: req.payload,
            req,
          })
        },
        () => {
          throw new Error('a later hook refused the save')
        },
      ],
    }).catch((error: unknown) => error)
    expect(failed).toMatchObject({ message: 'a later hook refused the save' })
    expect(joined).toBeTruthy()
    expect(await passkeysOf(user.id)).toBe(2)
    expect((await rawUser(payload, 'users', user.id)).sessions ?? []).toHaveLength(1)
    expect((await signedIn.get('/api/users/me')).json.user.id).toBe(user.id)
    expect((await rawUser(payload, 'users', user.id)).name).toBe('Test User')
  })

  // The documented trade-off: inside the caller's transaction a write conflict is not retried
  // (only the caller can retry a transaction), so the save fails and must be made again.
  it.runIf(adapter === 'mongo')(
    'fails the save cleanly, without retrying, when a refresh races it on MongoDB',
    async () => {
      const { signedIn, user } = await setUpLeaver()
      const sid = (await rawUser(payload, 'users', user.id)).sessions!.at(-1)!.id
      const warn = vi.spyOn(payload.logger, 'warn')
      let raced = false
      const spy = interceptSessionWrites(payload, 'users', async ({ write }) => {
        if (!raced) {
          raced = true
          // Commits a write to the user after the save's transaction first read it.
          expect((await signedIn.post('/api/users/refresh-token')).status).toBe(200)
        }
        return write()
      })
      let failed: unknown
      try {
        failed = await offboard(user.id, {
          beforeChange: [
            async ({ originalDoc, req }) => {
              await resetPasskeys({
                collection: 'users',
                id: originalDoc!.id as number | string,
                payload: req.payload,
                req,
              })
            },
          ],
        }).catch((error: unknown) => error)
      } finally {
        spy.mockRestore()
        warn.mockRestore()
      }
      expect(raced).toBe(true)
      expect(isWriteConflict(failed)).toBe(true)
      expect(warn).not.toHaveBeenCalledWith(
        expect.objectContaining({ msg: 'passkeys: retrying a session write' }),
      )
      // Nothing half-applied: the save, the passkeys and the session are all as they were.
      expect((await rawUser(payload, 'users', user.id)).name).toBe('Test User')
      expect(await passkeysOf(user.id)).toBe(2)
      expect((await signedIn.get('/api/users/me')).json.user.id).toBe(user.id)
      expect(
        (
          await payload.count({
            collection: 'passkey-challenge-uses',
            where: { challenge: { equals: `session:users:${sid}` } },
          } as never)
        ).totalDocs,
      ).toBe(0)
    },
  )
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
      stderr: expect.stringMatching(
        /No user in the users collection matches nobody@example\.test\./,
      ),
    })
  }, 120_000)
})
