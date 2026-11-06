import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import config from '../configs/single.js'
import { createClient, SERVER_URL } from '../helpers/api.js'
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

const STATUS = '/api/users/passkeys/status'

describe('status (review M9)', () => {
  it('tells anonymous callers only whether passkeys work here', async () => {
    expect((await createClient(config).post(STATUS)).json).toEqual({ available: true })
    expect(
      (await createClient(config, { origin: 'http://127.0.0.1:3000' }).post(STATUS)).json,
    ).toEqual({ available: false })
  })

  it('gives the signed-in owner the reason, the RP ID and their passkeys', async () => {
    const user = await createUser(payload, 'users')
    await insertPasskey(payload, { collection: 'users', userId: user.id })
    const client = await passwordClient(config, 'users', user.email)
    const res = await client.post(STATUS, {}, { headers: { Origin: 'http://127.0.0.1:3000' } })
    expect(res.json).toMatchObject({
      available: false,
      reason: 'origin_not_allowed',
      rpID: 'localhost',
    })
    expect(res.json.passkeys).toHaveLength(1)
    expect(res.json.signalUserId).toBeNull()
    expect(findSecretKeys(res.json)).toEqual([])
  })
})

describe('rename', () => {
  it("renames your own passkey and nobody else's", async () => {
    const alice = await createUser(payload, 'users')
    const bob = await createUser(payload, 'users')
    const mine = await insertPasskey(payload, { collection: 'users', userId: alice.id })
    const theirs = await insertPasskey(payload, { collection: 'users', userId: bob.id })
    const client = await passwordClient(config, 'users', alice.email)
    expect(
      (await client.post('/api/users/passkeys/rename', { id: mine.id, name: ' Phone ' })).json
        .passkey.name,
    ).toBe('Phone')
    expect(
      (await client.post('/api/users/passkeys/rename', { id: theirs.id, name: 'Mine now' })).status,
    ).toBe(404)
    expect(
      (await client.post('/api/users/passkeys/rename', { id: mine.id, name: '   ' })).status,
    ).toBe(400)
  })
})

describe('delete (review M6)', () => {
  it('removes your own passkey, and can sign out every other session', async () => {
    const alice = await createUser(payload, 'users')
    const authenticator = createSoftAuthenticator({ origin: SERVER_URL })
    const client = await passwordClient(config, 'users', alice.email)
    const { verify } = await registerPasskey(client, authenticator)
    const other = await passwordClient(config, 'users', alice.email)
    const res = await client.post('/api/users/passkeys/delete', {
      id: verify!.json.passkey.id,
      signOutOtherSessions: true,
    })
    expect(res.status).toBe(200)
    expect(res.json).toEqual({ remaining: 0, removed: true, signedOutSessions: 1 })
    expect((await other.get('/api/users/me')).json.user).toBeNull()
    expect((await client.get('/api/users/me')).json.user.id).toBe(alice.id)
    expect((await rawUser(payload, 'users', alice.id)).sessions).toHaveLength(1)
  })

  it('keeps other sessions unless asked', async () => {
    const alice = await createUser(payload, 'users')
    const row = await insertPasskey(payload, { collection: 'users', userId: alice.id })
    const client = await passwordClient(config, 'users', alice.email)
    const other = await passwordClient(config, 'users', alice.email)
    expect(
      (await client.post('/api/users/passkeys/delete', { id: row.id })).json.signedOutSessions,
    ).toBe(0)
    expect((await other.get('/api/users/me')).json.user.id).toBe(alice.id)
  })

  it("refuses someone else's passkey with 404", async () => {
    const alice = await createUser(payload, 'users')
    const bob = await createUser(payload, 'users')
    const theirs = await insertPasskey(payload, { collection: 'users', userId: bob.id })
    const client = await passwordClient(config, 'users', alice.email)
    expect((await client.post('/api/users/passkeys/delete', { id: theirs.id })).status).toBe(404)
    expect(
      (await payload.count({ collection: 'passkeys', where: { id: { equals: theirs.id } } }))
        .totalDocs,
    ).toBe(1)
  })
})

describe('deleting a user (single collection)', () => {
  it('deletes the user and their passkeys', async () => {
    const alice = await createUser(payload, 'users')
    const row = await insertPasskey(payload, { collection: 'users', userId: alice.id })
    await payload.delete({ collection: 'users', id: alice.id })
    expect((await payload.count({ collection: 'users', where: { id: { equals: alice.id } } })).totalDocs).toBe(0)
    expect((await payload.count({ collection: 'passkeys', where: { id: { equals: row.id } } })).totalDocs).toBe(0)
  })
})
