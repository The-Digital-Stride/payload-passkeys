import type * as PayloadModule from 'payload'

import { beforeEach, describe, expect, it, vi } from 'vitest'

const loginOperation = vi.fn()
vi.mock('payload', async (importOriginal) => ({
  ...(await importOriginal<typeof PayloadModule>()),
  loginOperation: (...args: unknown[]) => loginOperation(...args),
}))

const { reauthenticate, SignInRefused } = await import('../../src/server/mintSession.js')

const token = (sid: string) => `h.${Buffer.from(JSON.stringify({ sid })).toString('base64url')}.s`

/** A fake request with two users in memory; updateOne records which user's sessions changed. */
const fakeReq = () => {
  const users: Record<string, Record<string, unknown>> = {
    '1': { email: 'alice@example.test', id: 1, sessions: [{ id: 'old' }, { id: 'new' }] },
    '2': { id: 2, sessions: [{ id: 'other-new' }], username: 'alice@example.test' },
  }
  const updates: { id: unknown; sessions: unknown }[] = []
  const config = {
    auth: { loginWithUsername: { allowEmailLogin: true }, useSessions: true },
    flattenedFields: [],
    trash: false,
  }
  const req = {
    payload: {
      collections: { users: { config } },
      db: {
        findOne: async ({ where }: { where: { id: { equals: number } } }) => {
          const user = users[String(where.id.equals)]
          return user ? structuredClone(user) : null
        },
        updateOne: async ({ data, id }: { data: { sessions: unknown }; id: unknown }) => {
          updates.push({ id, sessions: data.sessions })
        },
      },
      logger: { error: vi.fn() },
    },
  }
  return { req: req as never, updates }
}

describe('reauthenticate checks who actually signed in', () => {
  beforeEach(() => loginOperation.mockReset())

  it('refuses when Payload signed in another account, ends its new session, keeps the old one', async () => {
    const { req, updates } = fakeReq()
    loginOperation.mockResolvedValue({ exp: 1, token: token('other-new'), user: { id: 2 } })
    const error = await reauthenticate({
      collectionSlug: 'users',
      password: 'pw',
      previousSid: 'old',
      req,
      userId: 1,
    }).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(SignInRefused)
    expect(error).toMatchObject({ reason: 'wrong_account' })
    expect(updates).toEqual([{ id: 2, sessions: [] }])
  })
})
