import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

import type { TestClient } from '../helpers/api.js'
import type { SoftAuthenticator } from '../helpers/softAuthenticator.js'
import type { TestUser } from '../helpers/users.js'

import { ENDPOINTS } from '../../src/shared/constants.js'
import config from '../configs/multi.js'
import { createClient, SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey, signInWithPasskey } from '../helpers/ceremonies.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, rawUser } from '../helpers/users.js'

/**
 * Review H3 end to end: on SQL, `users` 1 and `customers` 1 both exist, so a passkey, an access
 * rule or an ownership check that matches the ID alone would cross collections.
 */

const sql = (process.env.DATABASE_ADAPTER ?? 'mongo') !== 'mongo'

let payload: Payload
let user: TestUser
let customer: TestUser
let userKey: SoftAuthenticator
let customerKey: SoftAuthenticator
let userPasskeyId: number | string
let customerPasskeyId: number | string

const enrol = async (who: TestUser) => {
  const authenticator = createSoftAuthenticator({ origin: SERVER_URL })
  const { verify } = await registerPasskey(
    await passwordClient(config, who.collection, who.email),
    authenticator,
    { collection: who.collection, name: `${who.collection} key` },
  )
  expect(verify!.status).toBe(200)
  return { authenticator, id: verify!.json.passkey.id as number | string }
}

beforeAll(async () => {
  payload = await getPayload({ config })
  // The first row in each table of a freshly dropped database: on SQL both are id 1.
  user = await createUser(payload, 'users')
  customer = await createUser(payload, 'customers')
  ;({ authenticator: userKey, id: userPasskeyId } = await enrol(user))
  ;({ authenticator: customerKey, id: customerPasskeyId } = await enrol(customer))
})
afterAll(async () => {
  await payload.destroy()
})

const sessions = async (who: TestUser) =>
  ((await rawUser(payload, who.collection, who.id)).sessions ?? []).length

const lastSignInFailure = (spy: ReturnType<typeof vi.spyOn>) =>
  (spy.mock.calls as [{ msg?: string; reason?: string }][])
    .map(([line]) => line)
    .filter((line) => line.msg === 'passkeys.sign_in_failed')
    .at(-1)?.reason

const credentialIdsSeenBy = async (client: TestClient, collection: string) => {
  const status = await client.post(`/api/${collection}/passkeys/status`)
  expect(status.status).toBe(200)
  return (status.json.passkeys as { credentialId: string }[]).map((p) => p.credentialId)
}

describe('two auth collections (review H3)', () => {
  it.runIf(sql)('really do share an ID on SQL', () => {
    expect(String(user.id)).toBe(String(customer.id))
  })

  it("a customer's passkey cannot sign in to users, even with the same ID", async () => {
    const before = await sessions(user)
    const warn = vi.spyOn(payload.logger, 'warn')
    const client = createClient(config)
    const { verify } = await signInWithPasskey(client, customerKey, { collection: 'users' })
    expect(verify!.status).toBe(400)
    expect(verify!.json).toEqual({ error: 'sign_in_failed' })
    expect(lastSignInFailure(warn)).toBe('wrong_collection')
    warn.mockRestore()
    expect(client.cookies.has('payload-token')).toBe(false)
    expect((await client.get('/api/users/me')).json.user).toBeNull()
    expect(await sessions(user)).toBe(before)

    const ok = await signInWithPasskey(createClient(config), customerKey, {
      collection: 'customers',
    })
    expect(ok.verify!.status).toBe(200)
    expect(ok.verify!.json.user).toMatchObject({ email: customer.email, id: customer.id })
  })

  it("nor can a user's passkey sign in to customers", async () => {
    const before = await sessions(customer)
    const client = createClient(config)
    const { verify } = await signInWithPasskey(client, userKey, { collection: 'customers' })
    expect(verify!.json).toEqual({ error: 'sign_in_failed' })
    expect((await client.get('/api/customers/me')).json.user).toBeNull()
    expect(await sessions(customer)).toBe(before)

    const ok = await signInWithPasskey(createClient(config), userKey, { collection: 'users' })
    expect(ok.verify!.status).toBe(200)
    expect(ok.verify!.json.user).toMatchObject({ email: user.email, id: user.id })
  })

  it('a session minted for one collection is a session of that collection only', async () => {
    const asCustomer = createClient(config)
    expect(
      (await signInWithPasskey(asCustomer, customerKey, { collection: 'customers' })).verify!
        .status,
    ).toBe(200)
    expect((await asCustomer.get('/api/customers/me')).json.user.id).toBe(customer.id)
    expect((await asCustomer.get('/api/users/me')).json.user).toBeNull()
  })

  it("users with the same ID see only their own collection's passkeys", async () => {
    const asCustomer = await passwordClient(config, 'customers', customer.email)
    const asUser = await passwordClient(config, 'users', user.email)
    expect(await credentialIdsSeenBy(asCustomer, 'customers')).toEqual(customerKey.credentialIds())
    expect(await credentialIdsSeenBy(asUser, 'users')).toEqual(userKey.credentialIds())

    // The REST read access rule, not just the plugin's own lookups.
    const restIds = async (client: TestClient) =>
      ((await client.get('/api/passkeys?depth=0&limit=100')).json.docs as { id: unknown }[]).map(
        (doc) => doc.id,
      )
    expect(await restIds(asUser)).toEqual([userPasskeyId])
    expect(await restIds(asCustomer)).toEqual([customerPasskeyId])
    expect(
      (await asUser.get(`/api/passkeys/${String(customerPasskeyId)}?depth=0`)).status,
    ).toBeGreaterThanOrEqual(403)
  })

  it("and can rename and remove only their own collection's passkeys", async () => {
    const asCustomer = await passwordClient(config, 'customers', customer.email)
    const asUser = await passwordClient(config, 'users', user.email)
    const rename = (client: TestClient, collection: string, id: number | string) =>
      client.post(`/api/${collection}${ENDPOINTS.rename}`, { id, name: 'Taken' })
    const remove = (client: TestClient, collection: string, id: number | string) =>
      client.post(`/api/${collection}${ENDPOINTS.delete}`, { id })

    expect((await rename(asUser, 'users', customerPasskeyId)).status).toBe(404)
    expect((await remove(asUser, 'users', customerPasskeyId)).status).toBe(404)
    expect((await rename(asCustomer, 'customers', userPasskeyId)).status).toBe(404)
    expect((await remove(asCustomer, 'customers', userPasskeyId)).status).toBe(404)

    const names = async () =>
      (
        await payload.find({
          collection: 'passkeys',
          depth: 0,
          overrideAccess: true,
          sort: 'authCollection',
          where: { id: { in: [userPasskeyId, customerPasskeyId] } },
        })
      ).docs.map((doc) => [doc.authCollection, doc.name])
    expect(await names()).toEqual([
      ['customers', 'customers key'],
      ['users', 'users key'],
    ])

    // Each can still manage their own.
    expect((await rename(asUser, 'users', userPasskeyId)).json.passkey.name).toBe('Taken')
    expect((await rename(asCustomer, 'customers', customerPasskeyId)).json.passkey.name).toBe(
      'Taken',
    )
  })

  it.each([
    ENDPOINTS.registerOptions,
    ENDPOINTS.registerVerify,
    ENDPOINTS.reauth,
    ENDPOINTS.rename,
    ENDPOINTS.delete,
  ])('a users session cannot call the customers endpoint %s', async (endpoint) => {
    const asUser = await passwordClient(config, 'users', user.email)
    const res = await asUser.post(`/api/customers${endpoint}`, { id: customerPasskeyId })
    expect(res.status).toBe(401)
    expect(res.json).toEqual({ error: 'unauthorised' })
  })

  it("a users session gets only the anonymous answer from the customers' status", async () => {
    const asUser = await passwordClient(config, 'users', user.email)
    expect((await asUser.post(`/api/customers${ENDPOINTS.status}`)).json).toEqual({
      available: true,
    })
  })
})
