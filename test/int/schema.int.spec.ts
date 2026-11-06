import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import config from '../configs/multi.js'
import { createClient } from '../helpers/api.js'
import { insertPasskey } from '../helpers/passkeys.js'
import { findSecretKeys } from '../helpers/secrets.js'
import { createUser, PASSWORD } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const signIn = async (collection: 'customers' | 'users', email: string) => {
  const client = createClient(config)
  expect(
    (await client.post(`/api/${collection}/login`, { email, password: PASSWORD })).status,
  ).toBe(200)
  return client
}

describe('plugin collections', () => {
  it('are hidden, unlocked and out of GraphQL', () => {
    for (const slug of ['passkeys', 'passkey-challenges', 'passkey-challenge-uses'] as const) {
      const { config: collection } = payload.collections[slug]!
      expect(collection.admin.hidden).toBe(true)
      expect(collection.graphQL).toBe(false)
      expect(collection.lockDocuments).toBe(false)
    }
  })

  it('make the passkey owner polymorphic when two collections are configured', () => {
    const user = payload.collections.passkeys!.config.fields.find(
      (f) => 'name' in f && f.name === 'user',
    )
    expect(user).toMatchObject({
      maxDepth: 0,
      relationTo: ['users', 'customers'],
      type: 'relationship',
    })
  })
})

describe('passkeys access (review H3)', () => {
  it('lets a user read only their own passkeys, with no key material', async () => {
    const alice = await createUser(payload, 'users')
    const bob = await createUser(payload, 'users')
    await insertPasskey(payload, { collection: 'users', userId: alice.id })
    await insertPasskey(payload, { collection: 'users', userId: bob.id })
    const list = await (await signIn('users', alice.email)).get('/api/passkeys?depth=0&limit=100')
    expect(list.status).toBe(200)
    expect(list.json.docs).toHaveLength(1)
    expect(list.json.docs[0].collection).toBe('users')
    expect(findSecretKeys(list.json)).toEqual([])
  })

  it('refuses REST create, update and delete even for the owner', async () => {
    const alice = await createUser(payload, 'users')
    const row = await insertPasskey(payload, { collection: 'users', userId: alice.id })
    const client = await signIn('users', alice.email)
    expect((await client.post('/api/passkeys', { name: 'x' })).status).toBe(403)
    expect((await client.patch(`/api/passkeys/${row.id}`, { name: 'x' })).status).toBe(403)
    expect((await client.delete(`/api/passkeys/${row.id}`)).status).toBe(403)
  })

  it('refuses every API read of challenges and uses', async () => {
    const alice = await createUser(payload, 'users')
    const client = await signIn('users', alice.email)
    expect((await client.get('/api/passkey-challenges')).status).toBe(403)
    expect((await client.get('/api/passkey-challenge-uses')).status).toBe(403)
  })
})

describe('user fields', () => {
  it('never shows passkeyUserHandle, even to its owner', async () => {
    const alice = await createUser(payload, 'users')
    await payload.db.updateOne({
      collection: 'users',
      data: { passkeyUserHandle: 'h'.repeat(86) },
      id: alice.id,
      returning: false,
    })
    const me = await (await signIn('users', alice.email)).get('/api/users/me')
    expect(me.json.user.passkeyUserHandle).toBeUndefined()
  })

  it("deletes a user's passkeys with the user", async () => {
    const alice = await createUser(payload, 'users')
    await insertPasskey(payload, { collection: 'users', userId: alice.id })
    await payload.delete({ collection: 'users', id: alice.id })
    const left = await payload.count({
      collection: 'passkeys',
      where: { collection: { equals: 'users' }, 'user.value': { equals: alice.id } },
    })
    expect(left.totalDocs).toBe(0)
  })
})
