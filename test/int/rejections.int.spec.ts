import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ApiResult, TestClient } from '../helpers/api.js'
import type { CeremonyOverrides, SoftAuthenticator } from '../helpers/softAuthenticator.js'
import type { TestUser } from '../helpers/users.js'

import { browserKeyCookieName } from '../../src/server/cookies.js'
import config from '../configs/multi.js'
import { cloneWithCookies, createClient, SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey } from '../helpers/ceremonies.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, rawUser } from '../helpers/users.js'

/**
 * Every rejection path (design §9): each case runs one ceremony with one thing wrong, and expects
 * the generic failure, the intended reason in the log, no new session and (for registration)
 * nothing stored. A failure here is a security bug in an endpoint, never in the expectation.
 */

let payload: Payload
let warn: ReturnType<typeof vi.spyOn>
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})
beforeEach(() => {
  warn = vi.spyOn(payload.logger, 'warn')
})
afterEach(() => {
  warn.mockRestore()
})

type Collection = 'customers' | 'users'

// The test origin is http://localhost, so the browser-key cookies carry no __Host- prefix.
const AUTH_COOKIE = (collection: Collection) =>
  browserKeyCookieName('authentication', collection, false)
const REG_COOKIE = (collection: Collection) =>
  browserKeyCookieName('registration', collection, false)

const OPTIONS = (collection: Collection = 'users') => `/api/${collection}/passkeys/sign-in/options`
const VERIFY = (collection: Collection = 'users') => `/api/${collection}/passkeys/sign-in/verify`

const FAILURE_EVENTS = new Set([
  'passkeys.registration_failed',
  'passkeys.sign_in_failed',
  'passkeys.unknown_credential',
])

/** The `reason` of the last failure log line: proof the intended check refused, not another. */
const lastReason = (): string | undefined =>
  (warn.mock.calls as [{ msg?: string; reason?: string }][])
    .map(([line]) => line)
    .filter((line) => line.msg && FAILURE_EVENTS.has(line.msg))
    .at(-1)?.reason

const setCookieNames = (res: ApiResult): string[] =>
  res.headers.getSetCookie().map((line) => line.slice(0, line.indexOf('=')))

const sessionCount = async (collection: string, id: number | string) =>
  ((await rawUser(payload, collection, id)).sessions ?? []).length

const enrol = async (collection: Collection = 'users') => {
  const user = await createUser(payload, collection)
  const authenticator = createSoftAuthenticator({ origin: SERVER_URL })
  const { verify } = await registerPasskey(
    await passwordClient(config, collection, user.email),
    authenticator,
    { collection },
  )
  expect(verify!.status).toBe(200)
  return { authenticator, user }
}

const passkeysStored = async (collection: Collection, userId: number | string) =>
  (
    await payload.count({
      collection: 'passkeys',
      overrideAccess: true,
      where: {
        and: [
          { authCollection: { equals: collection } },
          { 'user.relationTo': { equals: collection } },
          { 'user.value': { equals: userId } },
        ],
      },
    })
  ).totalDocs

const credentialStored = async (credentialId: string) =>
  (
    await payload.count({
      collection: 'passkeys',
      overrideAccess: true,
      where: { credentialId: { equals: credentialId } },
    })
  ).totalDocs

type SignInContext = {
  authenticator: SoftAuthenticator
  client: TestClient
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  options: any
  user: TestUser
}

type SignInCase = {
  /** The body the browser sees; every case but an unknown credential is the bare generic one. */
  body?: Record<string, unknown>
  name: string
  overrides?: { credentialId?: string } & CeremonyOverrides
  /** The reason logged. A RegExp for the library's own refusals. */
  reason: RegExp | string
  /** Replaces the default "sign the options with the overrides and post it". */
  run?: (ctx: SignInContext) => Promise<ApiResult>
  setUp?: (ctx: Omit<SignInContext, 'client' | 'options'>) => Promise<void>
}

const GENERIC = { error: 'sign_in_failed' }

const signInCases: SignInCase[] = [
  {
    name: 'user verification missing',
    overrides: { userVerified: false },
    reason: /^verification_failed: User verification required/,
  },
  {
    name: 'user presence missing',
    overrides: { userPresent: false },
    reason: /^verification_failed: User not present/,
  },
  { name: 'bad signature', overrides: { badSignature: true }, reason: 'bad_signature' },
  {
    name: 'wrong origin in clientDataJSON',
    overrides: { origin: 'https://evil.test' },
    reason: /^verification_failed: Unexpected authentication response origin/,
  },
  {
    name: 'an allowed-looking origin on another port',
    overrides: { origin: 'http://localhost:3001' },
    reason: /^verification_failed: Unexpected authentication response origin/,
  },
  {
    name: 'wrong RP ID hash',
    overrides: { rpID: 'evil.test' },
    reason: /^verification_failed: Unexpected RP ID hash/,
  },
  {
    name: 'wrong ceremony type in clientDataJSON',
    overrides: { type: 'webauthn.create' },
    reason: /^verification_failed: Unexpected authentication response type/,
  },
  {
    name: 'a challenge the server never issued',
    overrides: { challenge: 'B'.repeat(43) },
    reason: 'unknown_challenge',
  },
  { name: 'no userHandle', overrides: { userHandle: null }, reason: 'user_handle_mismatch' },
  {
    name: 'a replayed assertion',
    reason: 'unknown_challenge',
    run: async ({ authenticator, client, options }) => {
      const response = await authenticator.authenticate(options)
      const first = await client.post(VERIFY(), { response })
      expect(first.status).toBe(200)
      return client.post(VERIFY(), { response })
    },
  },
  {
    name: 'an expired challenge',
    reason: 'expired',
    run: async ({ authenticator, client, options }) => {
      await payload.db.updateOne({
        collection: 'passkey-challenges',
        data: { expiresAt: new Date(Date.now() - 1000).toISOString() },
        returning: false,
        where: { challenge: { equals: options.challenge } },
      })
      return client.post(VERIFY(), { response: await authenticator.authenticate(options) })
    },
  },
  {
    name: 'another browser with no browser key (login CSRF)',
    reason: 'wrong_browser',
    run: async ({ authenticator, options }) =>
      createClient(config).post(VERIFY(), {
        response: await authenticator.authenticate(options),
      }),
  },
  {
    name: 'another browser holding its own browser key for another challenge (login CSRF)',
    reason: 'wrong_browser',
    run: async ({ authenticator, options }) => {
      const victim = createClient(config)
      expect((await victim.post(OPTIONS())).status).toBe(200)
      expect(victim.cookies.has(AUTH_COOKIE('users'))).toBe(true)
      return victim.post(VERIFY(), { response: await authenticator.authenticate(options) })
    },
  },
  {
    name: 'a registration challenge used for sign-in',
    reason: 'wrong_type',
    run: async ({ authenticator, client }) => {
      const owner = await passwordClient(
        config,
        'users',
        (await createUser(payload, 'users')).email,
      )
      const reg = await owner.post('/api/users/passkeys/register/options')
      expect(reg.status).toBe(200)
      // The registration challenge's own browser key, under the sign-in cookie name, so the
      // ceremony type is the only thing wrong.
      const browser = cloneWithCookies(config, client.cookies)
      browser.cookies.set(AUTH_COOKIE('users'), owner.cookies.get(REG_COOKIE('users'))!)
      return browser.post(VERIFY(), {
        response: await authenticator.authenticate({
          challenge: reg.json.options.challenge,
          rpId: 'localhost',
        }),
      })
    },
  },
  {
    name: 'a deleted credential',
    body: { error: 'sign_in_failed', unknownCredential: true },
    reason: 'unknown_credential',
    setUp: async ({ authenticator }) => {
      await payload.db.deleteMany({
        collection: 'passkeys',
        where: { credentialId: { equals: authenticator.credentialIds()[0] } },
      })
    },
  },
  {
    name: 'a malformed response',
    reason: 'malformed_response',
    run: ({ client }) =>
      client.post(VERIFY(), {
        response: { id: 'x', rawId: 'y', response: {}, type: 'public-key' },
      }),
  },
  {
    name: 'a response that is not an object',
    reason: 'malformed_response',
    run: ({ client }) => client.post(VERIFY(), { response: 'nope' }),
  },
]

describe.each(signInCases)('sign-in refuses $name', (testCase) => {
  it('with the generic failure and no new session', async () => {
    const { authenticator, user } = await enrol()
    await testCase.setUp?.({ authenticator, user })
    const before = await sessionCount('users', user.id)
    const client = createClient(config)
    const options = (await client.post(OPTIONS())).json.options
    const replay = testCase.name === 'a replayed assertion'

    const result = testCase.run
      ? await testCase.run({ authenticator, client, options, user })
      : await client.post(VERIFY(), {
          response: await authenticator.authenticate(options, testCase.overrides),
        })

    expect(result.status).toBe(400)
    expect(result.json).toEqual(testCase.body ?? GENERIC)
    expect(setCookieNames(result)).not.toContain('payload-token')
    const reason = lastReason()
    if (typeof testCase.reason === 'string') expect(reason).toBe(testCase.reason)
    else expect(reason).toMatch(testCase.reason)
    // The replay's first verify signs in legitimately; the second must not add a session.
    expect(await sessionCount('users', user.id)).toBe(before + (replay ? 1 : 0))
    if (!replay) expect(client.cookies.has('payload-token')).toBe(false)
  })
})

describe('sign-in refuses across auth collections and account rules', () => {
  it('a customers passkey presented to /api/users (review H3)', async () => {
    const { authenticator, user: customer } = await enrol('customers')
    const before = await sessionCount('customers', customer.id)
    const client = createClient(config)
    const options = (await client.post(OPTIONS('users'))).json.options
    const result = await client.post(VERIFY('users'), {
      response: await authenticator.authenticate(options),
    })
    expect(result.status).toBe(400)
    expect(result.json).toEqual(GENERIC)
    expect(lastReason()).toBe('wrong_collection')
    expect(setCookieNames(result)).not.toContain('payload-token')
    expect((await client.get('/api/users/me')).json.user).toBeNull()
    expect((await client.get('/api/customers/me')).json.user).toBeNull()
    expect(await sessionCount('customers', customer.id)).toBe(before)
  })

  it('a users challenge spent at /api/customers', async () => {
    const { authenticator, user: customer } = await enrol('customers')
    const before = await sessionCount('customers', customer.id)
    const client = createClient(config)
    const options = (await client.post(OPTIONS('users'))).json.options
    // The users browser key under the customers cookie name: only the collection is wrong.
    client.cookies.set(AUTH_COOKIE('customers'), client.cookies.get(AUTH_COOKIE('users'))!)
    const result = await client.post(VERIFY('customers'), {
      response: await authenticator.authenticate(options),
    })
    expect(result.status).toBe(400)
    expect(result.json).toEqual(GENERIC)
    expect(lastReason()).toBe('wrong_collection')
    expect(client.cookies.has('payload-token')).toBe(false)
    expect(await sessionCount('customers', customer.id)).toBe(before)
  })

  it('an unverified user (customers, auth.verify on)', async () => {
    const { authenticator, user: customer } = await enrol('customers')
    await payload.db.updateOne({
      collection: 'customers',
      data: { _verified: false },
      id: customer.id,
      returning: false,
    })
    const before = await sessionCount('customers', customer.id)
    const client = createClient(config)
    const options = (await client.post(OPTIONS('customers'))).json.options
    const result = await client.post(VERIFY('customers'), {
      response: await authenticator.authenticate(options),
    })
    expect(result.status).toBe(400)
    expect(result.json).toEqual(GENERIC)
    expect(lastReason()).toBe('unverified')
    expect(client.cookies.has('payload-token')).toBe(false)
    expect(await sessionCount('customers', customer.id)).toBe(before)
  })
})

const registrationCases: { name: string; overrides: CeremonyOverrides; reason: RegExp | string }[] =
  [
    {
      name: 'user verification missing',
      overrides: { userVerified: false },
      reason: /^verification_failed: User verification was required/,
    },
    {
      name: 'user presence missing',
      overrides: { userPresent: false },
      reason: /^verification_failed: User presence was required/,
    },
    {
      name: 'wrong origin',
      overrides: { origin: 'https://evil.test' },
      reason: /^verification_failed: Unexpected registration response origin/,
    },
    {
      name: 'wrong RP ID',
      overrides: { rpID: 'evil.test' },
      reason: /^verification_failed: Unexpected RP ID hash/,
    },
    {
      name: 'wrong type',
      overrides: { type: 'webauthn.get' },
      reason: /^verification_failed: Unexpected registration response type/,
    },
    {
      name: 'not discoverable (credProps.rk false, review L4)',
      overrides: { credPropsRk: false },
      reason: 'not_discoverable',
    },
    {
      name: 'a challenge the server never issued',
      overrides: { challenge: 'C'.repeat(43) },
      reason: 'unknown_challenge',
    },
  ]

describe.each(registrationCases)('registration refuses $name', ({ overrides, reason }) => {
  it('with the generic failure, storing nothing', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    const before = await sessionCount('users', user.id)
    const { response, verify } = await registerPasskey(
      client,
      createSoftAuthenticator({ origin: SERVER_URL }),
      { overrides },
    )
    expect(verify!.status).toBe(400)
    expect(verify!.json).toEqual({ error: 'registration_failed' })
    const logged = lastReason()
    if (typeof reason === 'string') expect(logged).toBe(reason)
    else expect(logged).toMatch(reason)
    expect(await passkeysStored('users', user.id)).toBe(0)
    expect(await credentialStored(response!.id)).toBe(0)
    expect(setCookieNames(verify!)).not.toContain('payload-token')
    expect(await sessionCount('users', user.id)).toBe(before)
  })
})

describe("registration refuses another user's challenge", () => {
  it("even with that user's browser key", async () => {
    const alice = await createUser(payload, 'users')
    const bob = await createUser(payload, 'users')
    const aliceClient = await passwordClient(config, 'users', alice.email)
    const bobClient = await passwordClient(config, 'users', bob.email)
    const options = await aliceClient.post('/api/users/passkeys/register/options')
    expect(options.status).toBe(200)
    const response = await createSoftAuthenticator({ origin: SERVER_URL }).register(
      options.json.options,
    )
    expect(aliceClient.cookies.has(REG_COOKIE('users'))).toBe(true)
    bobClient.cookies.set(REG_COOKIE('users'), aliceClient.cookies.get(REG_COOKIE('users'))!)
    const result = await bobClient.post('/api/users/passkeys/register/verify', { response })
    expect(result.status).toBe(400)
    expect(result.json).toEqual({ error: 'registration_failed' })
    expect(lastReason()).toBe('wrong_user')
    expect(await passkeysStored('users', alice.id)).toBe(0)
    expect(await passkeysStored('users', bob.id)).toBe(0)
    expect(await credentialStored(response.id)).toBe(0)
  })

  it('or a customers registration challenge spent at /api/users', async () => {
    const customer = await createUser(payload, 'customers')
    const user = await createUser(payload, 'users')
    const asCustomer = await passwordClient(config, 'customers', customer.email)
    const asUser = await passwordClient(config, 'users', user.email)
    const options = await asCustomer.post('/api/customers/passkeys/register/options')
    expect(options.status).toBe(200)
    const response = await createSoftAuthenticator({ origin: SERVER_URL }).register(
      options.json.options,
    )
    asUser.cookies.set(REG_COOKIE('users'), asCustomer.cookies.get(REG_COOKIE('customers'))!)
    const result = await asUser.post('/api/users/passkeys/register/verify', { response })
    expect(result.json).toEqual({ error: 'registration_failed' })
    expect(lastReason()).toBe('wrong_collection')
    expect(await credentialStored(response.id)).toBe(0)
  })
})
