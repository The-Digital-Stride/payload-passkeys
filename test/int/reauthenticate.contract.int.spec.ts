import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { reauthenticate, revokeSessions } from '../../src/server/mintSession.js'
import config from '../configs/single.js'
import { cloneWithCookies, createClient } from '../helpers/api.js'
import { requestFor } from '../helpers/requests.js'
import { createUser, PASSWORD, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const signedIn = async () => {
  const user = await createUser(payload, 'users')
  const client = createClient(config)
  expect(
    (await client.post('/api/users/login', { email: user.email, password: PASSWORD })).status,
  ).toBe(200)
  const sid = (await rawUser(payload, 'users', user.id)).sessions!.at(-1)!.id
  return { client, sid, user }
}

const reauth = async (
  client: ReturnType<typeof createClient>,
  userId: number | string,
  sid: string,
  password: string,
) =>
  reauthenticate({
    collectionSlug: 'users',
    password,
    previousSid: sid,
    req: await requestFor(config, '/api/users/passkeys/reauth', client),
    userId,
  })

describe('reauthenticate', () => {
  it('moves the browser to a new session and revokes the old one', async () => {
    const { client, sid, user } = await signedIn()
    const old = new Map(client.cookies)
    const result = await reauth(client, user.id, sid, PASSWORD)
    expect(result.sid).not.toBe(sid)
    const sessions = (await rawUser(payload, 'users', user.id)).sessions!.map((s) => s.id)
    expect(sessions).toContain(result.sid)
    expect(sessions).not.toContain(sid)
    expect((await cloneWithCookies(config, old).get('/api/users/me')).json.user).toBeNull()
    const fresh = createClient(config)
    fresh.setCookie(result.setCookie)
    expect((await fresh.get('/api/users/me')).json.user.id).toBe(user.id)
  })

  it('counts a wrong password towards the lockout and keeps the old session', async () => {
    const { client, sid, user } = await signedIn()
    await expect(reauth(client, user.id, sid, 'wrong password')).rejects.toThrow()
    expect((await rawUser(payload, 'users', user.id)).loginAttempts).toBe(1)
    expect((await client.get('/api/users/me')).json.user.id).toBe(user.id)
  })

  it('locks after maxLoginAttempts and then refuses the right password too', async () => {
    const { client, sid, user } = await signedIn()
    for (let i = 0; i < 5; i++) await reauth(client, user.id, sid, 'wrong').catch(() => undefined)
    await expect(reauth(client, user.id, sid, PASSWORD)).rejects.toMatchObject({
      name: 'LockedAuth',
    })
  })
})

describe('revokeSessions', () => {
  it('keeps only the named session, or removes all', async () => {
    const user = await createUser(payload, 'users')
    for (let i = 0; i < 3; i++) {
      await createClient(config).post('/api/users/login', { email: user.email, password: PASSWORD })
    }
    const ids = (await rawUser(payload, 'users', user.id)).sessions!.map((s) => s.id)
    const req = await requestFor(config, '/api/users/passkeys/delete')
    expect(
      await revokeSessions({ collectionSlug: 'users', keep: ids[0], req, userId: user.id }),
    ).toBe(2)
    expect((await rawUser(payload, 'users', user.id)).sessions!.map((s) => s.id)).toEqual([ids[0]])
    expect(await revokeSessions({ collectionSlug: 'users', req, userId: user.id })).toBe(1)
    expect((await rawUser(payload, 'users', user.id)).sessions ?? []).toHaveLength(0)
  })
})
