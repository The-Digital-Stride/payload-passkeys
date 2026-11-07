import type { Payload } from 'payload'

import { getPayload, JWT_AUTH_VERSION } from 'payload'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { testHooks } from '../../dev/testHooks.js'
import { mintSession, SignInRefused } from '../../src/server/mintSession.js'
import config from '../configs/multi.js'
import { cloneWithCookies, createClient } from '../helpers/api.js'
import { missingUserId, requestFor } from '../helpers/requests.js'
import { findSecretKeys } from '../helpers/secrets.js'
import { createUser, PASSWORD, rawUser } from '../helpers/users.js'

let payload: Payload

beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})
beforeEach(() => {
  testHooks.reset()
})

const mint = async (collection: 'customers' | 'users', userId: number | string) =>
  mintSession({
    collectionSlug: collection,
    req: await requestFor(config, `/api/${collection}/passkeys/sign-in/verify`),
    userId,
  })

const clientFrom = (setCookie: string) => {
  const client = createClient(config)
  client.setCookie(setCookie)
  return client
}

const passwordClient = async (email: string, collection = 'users') => {
  const client = createClient(config)
  const res = await client.post(`/api/${collection}/login`, { email, password: PASSWORD })
  expect(res.status).toBe(200)
  return client
}

const decodeSegment = (token: string, index: 0 | 1) =>
  JSON.parse(Buffer.from(token.split('.')[index]!, 'base64url').toString('utf8'))

describe('mintSession: the minted session is a native Payload session', () => {
  it('authenticates /me', async () => {
    const user = await createUser(payload, 'users')
    const minted = await mint('users', user.id)
    const me = await clientFrom(minted.setCookie).get('/api/users/me')
    expect(me.status).toBe(200)
    expect(me.json.user.id).toBe(user.id)
    expect(me.json.collection).toBe('users')
    expect(me.json.strategy).toBe('local-jwt')
  })

  it('signs with the current authVersion and carries sid, id and collection', async () => {
    const user = await createUser(payload, 'users')
    const minted = await mint('users', user.id)
    const token = clientFrom(minted.setCookie).cookies.get('payload-token')!
    expect(decodeSegment(token, 0).authVersion).toBe(JWT_AUTH_VERSION)
    const claims = decodeSegment(token, 1)
    expect(claims).toMatchObject({
      collection: 'users',
      email: user.email,
      id: user.id,
      sid: minted.sid,
    })
    expect(minted.body.exp).toBe(claims.exp)
  })

  it('is extended by /refresh-token', async () => {
    const user = await createUser(payload, 'users')
    const minted = await mint('users', user.id)
    const soon = new Date(Date.now() + 60_000).toISOString()
    const { sessions = [] } = await rawUser(payload, 'users', user.id)
    await payload.db.updateOne({
      collection: 'users',
      data: {
        sessions: sessions.map((s) => (s.id === minted.sid ? { ...s, expiresAt: soon } : s)),
      },
      id: user.id,
      returning: false,
    })
    const refreshed = await clientFrom(minted.setCookie).post('/api/users/refresh-token')
    expect(refreshed.status).toBe(200)
    expect(typeof refreshed.json.refreshedToken).toBe('string')
    const after = (await rawUser(payload, 'users', user.id)).sessions!.find(
      (s) => s.id === minted.sid,
    )!
    expect(Date.parse(after.expiresAt)).toBeGreaterThan(Date.now() + 3_600_000)
  })

  it('is revoked by logout', async () => {
    const user = await createUser(payload, 'users')
    const client = clientFrom((await mint('users', user.id)).setCookie)
    const saved = new Map(client.cookies)
    expect((await client.post('/api/users/logout')).status).toBe(200)
    expect((await cloneWithCookies(config, saved).get('/api/users/me')).json.user).toBeNull()
  })

  it('is revoked by "log out of all sessions" from another session', async () => {
    const user = await createUser(payload, 'users')
    const minted = clientFrom((await mint('users', user.id)).setCookie)
    const other = await passwordClient(user.email)
    expect((await other.post('/api/users/logout?allSessions=true')).status).toBe(200)
    expect((await minted.get('/api/users/me')).json.user).toBeNull()
  })

  it('is revoked by a password change made from another session', async () => {
    const user = await createUser(payload, 'users')
    const minted = clientFrom((await mint('users', user.id)).setCookie)
    const other = await passwordClient(user.email)
    const changed = await other.patch(`/api/users/${user.id}`, {
      password: 'a different long passphrase',
    })
    expect(changed.status).toBe(200)
    expect((await minted.get('/api/users/me')).json.user).toBeNull()
    expect((await other.get('/api/users/me')).json.user.id).toBe(user.id)
  })

  it('survives a password change made from itself (core keeps the current session)', async () => {
    const user = await createUser(payload, 'users')
    const minted = clientFrom((await mint('users', user.id)).setCookie)
    expect(
      (await minted.patch(`/api/users/${user.id}`, { password: 'another long passphrase' })).status,
    ).toBe(200)
    expect((await minted.get('/api/users/me')).json.user.id).toBe(user.id)
  })
})

describe('mintSession: account rules', () => {
  it('refuses a user that does not exist', async () => {
    await expect(mint('users', missingUserId())).rejects.toMatchObject({ reason: 'user_missing' })
  })

  it('refuses an unverified user', async () => {
    const user = await createUser(payload, 'customers')
    await payload.db.updateOne({
      collection: 'customers',
      data: { _verified: false },
      id: user.id,
      returning: false,
    })
    const error = await mint('customers', user.id).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(SignInRefused)
    expect((error as SignInRefused).reason).toBe('unverified')
    expect((await rawUser(payload, 'customers', user.id)).sessions ?? []).toHaveLength(0)
  })

  it('does not refuse a locked user, reports it, and resets the attempts (review M5)', async () => {
    const user = await createUser(payload, 'users')
    const lockUntil = new Date(Date.now() + 600_000).toISOString()
    await payload.db.updateOne({
      collection: 'users',
      data: { lockUntil, loginAttempts: 5 },
      id: user.id,
      returning: false,
    })
    const minted = await mint('users', user.id)
    expect(minted.wasLocked).toBe(true)
    const raw = await rawUser(payload, 'users', user.id)
    expect(raw.loginAttempts).toBe(0)
    expect(raw.lockUntil ?? null).toBeNull()
    expect((await clientFrom(minted.setCookie).get('/api/users/me')).json.user.id).toBe(user.id)
  })

  it('revokes the new session when a beforeLogin hook throws', async () => {
    const user = await createUser(payload, 'users')
    testHooks.beforeLogin = () => {
      throw new Error('blocked by host rule')
    }
    await expect(mint('users', user.id)).rejects.toThrow('blocked by host rule')
    expect((await rawUser(payload, 'users', user.id)).sessions ?? []).toHaveLength(0)
  })

  it('revokes the new session when onSignIn throws', async () => {
    const user = await createUser(payload, 'users')
    const req = await requestFor(config, '/api/users/passkeys/sign-in/verify')
    await expect(
      mintSession({
        collectionSlug: 'users',
        onSignIn: () => {
          throw new Error('geo rule')
        },
        req,
        userId: user.id,
      }),
    ).rejects.toThrow('geo rule')
    expect((await rawUser(payload, 'users', user.id)).sessions ?? []).toHaveLength(0)
  })

  it('passes beforeLogin the user and afterLogin the token', async () => {
    const user = await createUser(payload, 'users')
    const seen: Record<string, unknown>[] = []
    testHooks.beforeLogin = (args) => void seen.push({ hook: 'before', ...args })
    testHooks.afterLogin = (args) => void seen.push({ hook: 'after', ...args })
    await mint('users', user.id)
    expect(seen.map((s) => s.hook)).toEqual(['before', 'after'])
    expect((seen[0]!.user as { id: unknown }).id).toBe(user.id)
    expect(typeof seen[1]!.token).toBe('string')
  })
})

describe('mintSession: response body', () => {
  it('has the shape useAuth().setUser expects', async () => {
    const user = await createUser(payload, 'users')
    const { body } = await mint('users', user.id)
    expect(typeof body.exp).toBe('number')
    expect(typeof body.token).toBe('string')
    expect(body.user).toMatchObject({ collection: 'users', email: user.email, id: user.id })
  })

  it('omits the token when removeTokenFromResponses is on', async () => {
    const user = await createUser(payload, 'customers')
    const { body } = await mint('customers', user.id)
    expect(body.token).toBeUndefined()
  })

  it('never contains hash, salt, sessions, apiKey or other secrets (review M1)', async () => {
    const user = await createUser(payload, 'users', {
      apiKey: crypto.randomUUID(),
      enableAPIKey: true,
    })
    const { body } = await mint('users', user.id)
    expect(findSecretKeys(body)).toEqual([])
  })
})
