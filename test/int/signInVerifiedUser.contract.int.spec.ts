import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import { testHooks } from '../../dev/testHooks.js'
import { signInVerifiedUser, SignInRefused } from '../../src/index.js'
import config from '../configs/multi.js'
import { createClient, SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey, signInWithPasskey } from '../helpers/ceremonies.js'
import { missingUserId } from '../helpers/requests.js'
import { findSecretKeys } from '../helpers/secrets.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, rawUser } from '../helpers/users.js'

let payload: Payload

beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})
beforeEach(() => {
  testHooks.reset()
  vi.restoreAllMocks()
})

const clientFrom = (setCookie: string) => {
  const client = createClient(config)
  client.setCookie(setCookie)
  return client
}

const signIn = (collection: string, userId: number | string, headers?: Headers) =>
  signInVerifiedUser({ collection, headers, payload, userId })

describe('signInVerifiedUser: the session is a native Payload session', () => {
  it('returns a cookie whose token authenticates /me', async () => {
    const user = await createUser(payload, 'users')
    const result = await signIn('users', user.id)
    const me = await clientFrom(result.setCookie).get('/api/users/me')
    expect(me.status).toBe(200)
    expect(me.json.user.id).toBe(user.id)
    expect(me.json.strategy).toBe('local-jwt')
    expect(result.exp).toBe(me.json.exp)
    expect(result.user).toMatchObject({ collection: 'users', email: user.email, id: user.id })
    expect(findSecretKeys(result)).toEqual([])
  })

  it('adds exactly one session, created now, so a passkey can be added straight away', async () => {
    const user = await createUser(payload, 'users')
    const result = await signIn('users', user.id)
    const sessions = (await rawUser(payload, 'users', user.id)).sessions ?? []
    expect(sessions).toHaveLength(1)
    expect(Math.abs(Date.parse(sessions[0]!.createdAt!) - Date.now())).toBeLessThan(10_000)
    const options = await clientFrom(result.setCookie).post('/api/users/passkeys/register/options')
    expect(options.status).toBe(200)
  })

  it('clears failed-login attempts and a lock', async () => {
    const user = await createUser(payload, 'users')
    await payload.db.updateOne({
      collection: 'users',
      data: { lockUntil: new Date(Date.now() + 600_000).toISOString(), loginAttempts: 5 },
      id: user.id,
      returning: false,
    })
    await signIn('users', user.id)
    const raw = await rawUser(payload, 'users', user.id)
    expect(raw.loginAttempts).toBe(0)
    expect(raw.lockUntil ?? null).toBeNull()
  })

  it('works for every configured collection', async () => {
    const customer = await createUser(payload, 'customers')
    const result = await signIn('customers', customer.id)
    expect((await clientFrom(result.setCookie).get('/api/customers/me')).json.user.id).toBe(
      customer.id,
    )
  })
})

describe('signInVerifiedUser: hooks', () => {
  it('lets a beforeLogin hook refuse it, leaving no session', async () => {
    const user = await createUser(payload, 'users')
    testHooks.beforeLogin = () => {
      throw new Error('disabled user')
    }
    await expect(signIn('users', user.id)).rejects.toThrow('disabled user')
    expect((await rawUser(payload, 'users', user.id)).sessions ?? []).toHaveLength(0)
  })

  it("passes onSignIn method 'sso' and no passkey", async () => {
    const user = await createUser(payload, 'users')
    let seen: Record<string, unknown> | undefined
    testHooks.onSignIn = (args) => void (seen = args)
    await signIn('users', user.id)
    expect(seen).toMatchObject({ collection: 'users', method: 'sso' })
    expect(seen).not.toHaveProperty('passkey')
    expect((seen!.user as { id: unknown }).id).toBe(user.id)
    expect(findSecretKeys(seen!.user)).toEqual([])
  })

  it('lets onSignIn refuse it, leaving no session', async () => {
    const user = await createUser(payload, 'users')
    testHooks.onSignIn = () => {
      throw new Error('outside office hours')
    }
    await expect(signIn('users', user.id)).rejects.toThrow('outside office hours')
    expect((await rawUser(payload, 'users', user.id)).sessions ?? []).toHaveLength(0)
  })

  it("gives hooks the caller's request headers", async () => {
    const user = await createUser(payload, 'users')
    const seen: (null | string)[] = []
    const header = (args: Record<string, unknown>) =>
      (args.req as { headers: Headers }).headers.get('x-forwarded-for')
    testHooks.beforeLogin = (args) => void seen.push(header(args))
    testHooks.onSignIn = (args) => void seen.push(header(args))
    await signIn('users', user.id, new Headers({ 'x-forwarded-for': '203.0.113.7' }))
    expect(seen).toEqual(['203.0.113.7', '203.0.113.7'])
  })
})

describe('signInVerifiedUser: refusals', () => {
  const writesDuring = async (run: () => Promise<unknown>) => {
    const updateOne = vi.spyOn(payload.db, 'updateOne')
    const create = vi.spyOn(payload.db, 'create')
    const error = await run().catch((e: unknown) => e)
    const writes = updateOne.mock.calls.length + create.mock.calls.length
    updateOne.mockRestore()
    create.mockRestore()
    return { error, writes }
  }

  it('refuses a collection the plugin does not cover, before any write', async () => {
    const user = await createUser(payload, 'users')
    for (const collection of ['passkeys', 'nope']) {
      const { error, writes } = await writesDuring(() => signIn(collection, user.id))
      expect(error).toBeInstanceOf(Error)
      expect((error as Error).message).toMatch(/is not a passkeys collection/)
      expect(writes).toBe(0)
    }
  })

  it('refuses a user that does not exist, before any write', async () => {
    const { error, writes } = await writesDuring(() => signIn('users', missingUserId()))
    expect(error).toBeInstanceOf(SignInRefused)
    expect(error).toMatchObject({
      message: 'Sign-in refused: user_missing',
      name: 'SignInRefused',
      reason: 'user_missing',
    })
    expect(writes).toBe(0)
  })
})

describe('signInVerifiedUser: logs', () => {
  it("logs passkeys.signed_in with method 'sso'", async () => {
    const user = await createUser(payload, 'users')
    const info = vi.spyOn(payload.logger, 'info')
    await signIn('users', user.id)
    expect(info).toHaveBeenCalledWith({
      collection: 'users',
      event: 'passkeys.signed_in',
      method: 'sso',
      msg: 'passkeys.signed_in',
      userId: user.id,
    })
    expect(info).not.toHaveBeenCalledWith(
      expect.objectContaining({ event: 'passkeys.signed_in_while_locked' }),
    )
  })

  it('logs passkeys.signed_in_while_locked for a locked user', async () => {
    const user = await createUser(payload, 'users')
    await payload.db.updateOne({
      collection: 'users',
      data: { lockUntil: new Date(Date.now() + 600_000).toISOString(), loginAttempts: 5 },
      id: user.id,
      returning: false,
    })
    const info = vi.spyOn(payload.logger, 'info')
    await signIn('users', user.id)
    expect(info).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'passkeys.signed_in_while_locked',
        method: 'sso',
        userId: user.id,
      }),
    )
  })
})

describe("a passkey sign-in, for comparison: method 'passkey'", () => {
  it("passes onSignIn method 'passkey' with the passkey, and logs it", async () => {
    const user = await createUser(payload, 'users')
    const authenticator = createSoftAuthenticator({ origin: SERVER_URL })
    const { verify: registered } = await registerPasskey(
      await passwordClient(config, 'users', user.email),
      authenticator,
    )
    expect(registered!.status).toBe(200)
    let seen: Record<string, unknown> | undefined
    testHooks.onSignIn = (args) => void (seen = args)
    const info = vi.spyOn(payload.logger, 'info')
    const { verify } = await signInWithPasskey(createClient(config), authenticator)
    expect(verify!.status).toBe(200)
    expect(seen).toMatchObject({
      collection: 'users',
      method: 'passkey',
      passkey: { credentialId: authenticator.credentialIds()[0] },
    })
    expect(info).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'passkeys.signed_in',
        method: 'passkey',
        userId: user.id,
      }),
    )
  })
})
