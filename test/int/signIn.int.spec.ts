import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { testHooks } from '../../dev/testHooks.js'
import config from '../configs/single.js'
import { createClient, SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey, signInWithPasskey } from '../helpers/ceremonies.js'
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
beforeEach(() => testHooks.reset())

const enrolled = async (
  authOptions: Partial<Parameters<typeof createSoftAuthenticator>[0]> = {},
) => {
  const user = await createUser(payload, 'users')
  const authenticator = createSoftAuthenticator({ origin: SERVER_URL, ...authOptions })
  const { verify } = await registerPasskey(
    await passwordClient(config, 'users', user.email),
    authenticator,
  )
  expect(verify!.status).toBe(200)
  return { authenticator, user }
}

const row = async (credentialId: string) =>
  (
    await payload.find({
      collection: 'passkeys',
      overrideAccess: true,
      where: { credentialId: { equals: credentialId } },
    })
  ).docs[0]!

describe('sign-in/options', () => {
  it('names no credentials and requires UV', async () => {
    const client = createClient(config)
    const res = await client.post('/api/users/passkeys/sign-in/options')
    expect(res.status).toBe(200)
    expect(res.json.options).toMatchObject({
      allowCredentials: [],
      rpId: 'localhost',
      timeout: 300_000,
      userVerification: 'required',
    })
    expect(client.cookies.has('payload-passkeys-auth-users')).toBe(true)
  })

  it('answers 429 busy at the anonymous cap (test config: 50)', async () => {
    for (let i = 0; i < 50; i++)
      await createClient(config).post('/api/users/passkeys/sign-in/options')
    const res = await createClient(config).post('/api/users/passkeys/sign-in/options')
    expect(res.status).toBe(429)
    expect(res.json).toEqual({ error: 'busy' })
    await payload.db.deleteMany({ collection: 'passkey-challenges', where: {} })
  })
})

describe('sign-in/verify', () => {
  it('signs in with a native session cookie and the body setUser expects', async () => {
    const { authenticator, user } = await enrolled()
    const client = createClient(config)
    const { verify } = await signInWithPasskey(client, authenticator)
    expect(verify!.status).toBe(200)
    expect(verify!.json).toMatchObject({
      exp: expect.any(Number),
      user: { email: user.email, id: user.id },
    })
    expect(findSecretKeys(verify!.json)).toEqual([])
    expect(client.cookies.has('payload-token')).toBe(true)
    expect(client.cookies.has('payload-passkeys-auth-users')).toBe(false)
    expect((await client.get('/api/users/me')).json.user.id).toBe(user.id)
    expect((await row(authenticator.credentialIds()[0]!)).lastUsedAt).toBeTruthy()
  })

  it('gives an unknown credential a generic failure plus the hint for signalUnknownCredential', async () => {
    const { authenticator } = await enrolled()
    await payload.db.deleteMany({
      collection: 'passkeys',
      where: { credentialId: { equals: authenticator.credentialIds()[0] } },
    })
    const { verify } = await signInWithPasskey(createClient(config), authenticator)
    expect(verify!.status).toBe(400)
    expect(verify!.json).toEqual({ error: 'sign_in_failed', unknownCredential: true })
  })

  it("refuses an assertion whose userHandle is not the row's (review L4)", async () => {
    const { authenticator } = await enrolled()
    const { verify } = await signInWithPasskey(createClient(config), authenticator, {
      overrides: { userHandle: 'b3RoZXI' },
    })
    expect(verify!.json).toEqual({ error: 'sign_in_failed' })
  })

  it('signs in a password-locked user, logs it and resets attempts (review M5)', async () => {
    const { authenticator, user } = await enrolled()
    await payload.db.updateOne({
      collection: 'users',
      data: { lockUntil: new Date(Date.now() + 600_000).toISOString(), loginAttempts: 5 },
      id: user.id,
      returning: false,
    })
    const { verify } = await signInWithPasskey(createClient(config), authenticator)
    expect(verify!.status).toBe(200)
    expect((await rawUser(payload, 'users', user.id)).loginAttempts).toBe(0)
  })

  it('refuses when a beforeLogin hook throws, and leaves no session', async () => {
    const { authenticator, user } = await enrolled()
    const before = (await rawUser(payload, 'users', user.id)).sessions!.length
    testHooks.beforeLogin = () => {
      throw new Error('no logins on Sundays')
    }
    const { verify } = await signInWithPasskey(createClient(config), authenticator)
    expect(verify!.json).toEqual({ error: 'sign_in_failed' })
    expect((await rawUser(payload, 'users', user.id)).sessions!.length).toBe(before)
  })

  it('passes onSignIn the public passkey', async () => {
    const { authenticator } = await enrolled()
    let seen: unknown
    testHooks.onSignIn = (args) => void (seen = args.passkey)
    await signInWithPasskey(createClient(config), authenticator)
    expect(seen).toMatchObject({ credentialId: authenticator.credentialIds()[0] })
    expect(findSecretKeys(seen)).toEqual([])
  })
})

describe('counter and flags (review M7)', () => {
  it('refuses a device-bound passkey whose counter did not increase', async () => {
    const { authenticator } = await enrolled({ backupEligible: false, incrementCounter: true })
    expect((await signInWithPasskey(createClient(config), authenticator)).verify!.status).toBe(200)
    const replayedCounter = await signInWithPasskey(createClient(config), authenticator, {
      overrides: { counter: 1 },
    })
    expect(replayedCounter.verify!.json).toEqual({ error: 'sign_in_failed' })
  })

  it('lets a synced passkey regress without lowering the stored counter', async () => {
    const { authenticator } = await enrolled({ incrementCounter: true })
    await signInWithPasskey(createClient(config), authenticator, { overrides: { counter: 7 } })
    expect(
      (await signInWithPasskey(createClient(config), authenticator, { overrides: { counter: 2 } }))
        .verify!.status,
    ).toBe(200)
    expect((await row(authenticator.credentialIds()[0]!)).counter).toBe(7)
  })

  it('refuses a change of device type and follows the backup state', async () => {
    const { authenticator } = await enrolled({ backupState: false })
    expect(
      (
        await signInWithPasskey(createClient(config), authenticator, {
          overrides: { backupEligible: false, backupState: false },
        })
      ).verify!.status,
    ).toBe(400)
    expect(
      (
        await signInWithPasskey(createClient(config), authenticator, {
          overrides: { backupState: true },
        })
      ).verify!.status,
    ).toBe(200)
    expect((await row(authenticator.credentialIds()[0]!)).backedUp).toBe(true)
  })
})
