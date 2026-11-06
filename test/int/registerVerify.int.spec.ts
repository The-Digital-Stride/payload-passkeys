import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import config from '../configs/single.js'
import { SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey } from '../helpers/ceremonies.js'
import { insertPasskey } from '../helpers/passkeys.js'
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

const setUp = async (authOptions: Partial<Parameters<typeof createSoftAuthenticator>[0]> = {}) => {
  const user = await createUser(payload, 'users')
  const client = await passwordClient(config, 'users', user.email)
  const authenticator = createSoftAuthenticator({ origin: SERVER_URL, ...authOptions })
  return { authenticator, client, user }
}

const rows = (userId: number | string) =>
  payload.find({
    collection: 'passkeys',
    overrideAccess: true,
    where: { user: { equals: userId } },
  })

describe('register/verify', () => {
  it('stores a synced passkey and returns only public fields', async () => {
    const { authenticator, client, user } = await setUp({
      aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4',
    })
    const { verify } = await registerPasskey(client, authenticator)
    expect(verify!.status).toBe(200)
    expect(findSecretKeys(verify!.json)).toEqual([])
    expect(verify!.json.passkey).toMatchObject({
      aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4',
      backedUp: true,
      deviceType: 'multiDevice',
      name: 'Google Password Manager',
      rpID: 'localhost',
    })
    const [row] = (await rows(user.id)).docs
    expect(row).toMatchObject({
      collection: 'users',
      counter: 0,
      credentialId: authenticator.credentialIds()[0],
      userHandle: (await rawUser(payload, 'users', user.id)).passkeyUserHandle,
    })
    expect(client.cookies.has('payload-passkeys-reg-users')).toBe(false)
  })

  it('stores a device-bound passkey and a chosen name, trimmed', async () => {
    const { authenticator, client, user } = await setUp({ backupEligible: false })
    const { verify } = await registerPasskey(client, authenticator, {
      name: '  Work laptop \u0007 ',
    })
    expect(verify!.json.passkey).toMatchObject({
      backedUp: false,
      deviceType: 'singleDevice',
      name: 'Work laptop',
    })
    expect((await rows(user.id)).totalDocs).toBe(1)
  })

  it('accepts a missing credProps and refuses rk: false (review L4)', async () => {
    const a = await setUp()
    expect(
      (await registerPasskey(a.client, a.authenticator, { overrides: { credPropsRk: null } }))
        .verify!.status,
    ).toBe(200)
    const b = await setUp()
    const refused = await registerPasskey(b.client, b.authenticator, {
      overrides: { credPropsRk: false },
    })
    expect(refused.verify!.status).toBe(400)
    expect(refused.verify!.json).toEqual({ error: 'registration_failed' })
  })

  it('refuses a replayed response', async () => {
    const { authenticator, client } = await setUp()
    const first = await registerPasskey(client, authenticator)
    expect(first.verify!.status).toBe(200)
    const again = await client.post('/api/users/passkeys/register/verify', {
      response: first.response,
    })
    expect(again.json).toEqual({ error: 'registration_failed' })
  })

  it('refuses a credential ID stored for anyone', async () => {
    const { authenticator, client } = await setUp()
    const options = await client.post('/api/users/passkeys/register/options')
    const response = await authenticator.register(options.json.options)
    const other = await createUser(payload, 'users')
    await insertPasskey(payload, {
      collection: 'users',
      credentialId: response.id,
      userId: other.id,
    })
    const res = await client.post('/api/users/passkeys/register/verify', { response })
    expect(res.json).toEqual({ error: 'registration_failed' })
  })
})
