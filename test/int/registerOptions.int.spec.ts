import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import config from '../configs/single.js'
import { createClient } from '../helpers/api.js'
import { ageNewestSession, passwordClient } from '../helpers/ceremonies.js'
import { insertPasskey } from '../helpers/passkeys.js'
import { createUser, PASSWORD, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const OPTIONS = '/api/users/passkeys/register/options'

describe('register/options', () => {
  it('needs a cookie session of this collection', async () => {
    expect((await createClient(config).post(OPTIONS)).json).toEqual({ error: 'unauthorised' })
    const apiKey = crypto.randomUUID()
    await createUser(payload, 'users', { apiKey, enableAPIKey: true })
    const res = await createClient(config).post(
      OPTIONS,
      {},
      { headers: { Authorization: `users API-Key ${apiKey}` } },
    )
    expect(res.status).toBe(403)
  })

  it('returns discoverable, UV-required creation options bound to this browser', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    const res = await client.post(OPTIONS)
    expect(res.status).toBe(200)
    const handle = (await rawUser(payload, 'users', user.id)).passkeyUserHandle
    expect(handle).toMatch(/^[A-Za-z0-9_-]{86}$/)
    expect(res.json.options).toMatchObject({
      attestation: 'none',
      authenticatorSelection: {
        requireResidentKey: true,
        residentKey: 'required',
        userVerification: 'required',
      },
      extensions: { credProps: true },
      rp: { id: 'localhost' },
      timeout: 300_000,
      user: { displayName: 'Test User', id: handle, name: user.email },
    })
    expect(res.json.options.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(res.json.options.pubKeyCredParams.map((p: { alg: number }) => p.alg)).toEqual([
      -8, -7, -257,
    ])
    expect(client.cookies.has('payload-passkeys-reg-users')).toBe(true)
  })

  it('keeps the same user handle across calls', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    const a = await client.post(OPTIONS)
    const b = await client.post(OPTIONS)
    expect(a.json.options.user.id).toBe(b.json.options.user.id)
  })

  it('lists existing passkeys in excludeCredentials', async () => {
    const user = await createUser(payload, 'users')
    const row = await insertPasskey(payload, { collection: 'users', userId: user.id })
    const res = await (await passwordClient(config, 'users', user.email)).post(OPTIONS)
    expect(res.json.options.excludeCredentials.map((c: { id: string }) => c.id)).toEqual([
      row.credentialId,
    ])
  })

  it('asks for the password when the session is older than freshSessionMinutes', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    await ageNewestSession(payload, 'users', user.id, 11)
    const res = await client.post(OPTIONS)
    expect(res.status).toBe(403)
    expect(res.json).toEqual({ error: 'reauth_required' })
  })

  it('stops at the per-user cap', async () => {
    const user = await createUser(payload, 'users')
    for (let i = 0; i < 3; i++)
      await insertPasskey(payload, { collection: 'users', userId: user.id })
    const res = await (await passwordClient(config, 'users', user.email)).post(OPTIONS)
    expect(res.status).toBe(409)
    expect(res.json).toEqual({ error: 'too_many_passkeys' })
  })
})

describe('reauth (review H1)', () => {
  it('refuses a wrong password and counts it', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    const res = await client.post('/api/users/passkeys/reauth', { password: 'wrong' })
    expect(res.status).toBe(401)
    expect(res.json).toEqual({ error: 'reauth_failed' })
    expect((await rawUser(payload, 'users', user.id)).loginAttempts).toBe(1)
  })

  it('moves the browser to a fresh session so register/options works again', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    await ageNewestSession(payload, 'users', user.id, 30)
    const before = (await rawUser(payload, 'users', user.id)).sessions!.map((s) => s.id)
    const res = await client.post('/api/users/passkeys/reauth', { password: PASSWORD })
    expect(res.status).toBe(200)
    expect(res.json.user.id).toBe(user.id)
    const after = (await rawUser(payload, 'users', user.id)).sessions!.map((s) => s.id)
    expect(after.some((id) => before.includes(id))).toBe(false)
    expect((await client.post(OPTIONS)).status).toBe(200)
  })

  it('takes the identifier from the session, never the body', async () => {
    const victim = await createUser(payload, 'users')
    const attacker = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', attacker.email)
    await client.post('/api/users/passkeys/reauth', { email: victim.email, password: 'guess' })
    expect((await rawUser(payload, 'users', victim.id)).loginAttempts ?? 0).toBe(0)
  })
})
