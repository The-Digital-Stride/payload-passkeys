/**
 * Writes other than /refresh-token can put a revoked session back. Payload's update fills fields
 * the request left out from the stored document, `sessions` included (field update access is
 * false, but beforeValidate's fallback uses the original document), and logout rewrites the whole
 * list. Either one that read the user before the revoke and writes after it restores every revoked
 * session. These tests hold that write back until the revoke has finished, so the race is
 * deterministic, and require that a revoked session can never authenticate again.
 */
import type { Payload } from 'payload'

import { GRAPHQL_POST } from '@payloadcms/next/routes'
import { getPayload } from 'payload'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'

import type { TestClient } from '../helpers/api.js'

import config from '../configs/single.js'
import { SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey } from '../helpers/ceremonies.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterEach(() => {
  vi.restoreAllMocks()
})
afterAll(async () => {
  await payload.destroy()
})

const DELETE = '/api/users/passkeys/delete'
const CHALLENGE_USES = 'passkey-challenge-uses'

const sessionIds = async (id: number | string) =>
  ((await rawUser(payload, 'users', id)).sessions ?? []).map((session) => session.id)

/** A user with one passkey, signed in from the owner's browser and `others` more. */
const setUp = async (others = 1) => {
  const owner = await createUser(payload, 'users')
  const ownerClient = await passwordClient(config, 'users', owner.email)
  const { verify } = await registerPasskey(
    ownerClient,
    createSoftAuthenticator({ origin: SERVER_URL }),
  )
  const passkeyId = verify!.json.passkey.id as number | string
  const [ownerSid] = await sessionIds(owner.id)
  const clients: TestClient[] = []
  for (let i = 0; i < others; i++) clients.push(await passwordClient(config, 'users', owner.email))
  const revokedSids = (await sessionIds(owner.id)).filter((sid) => sid !== ownerSid)
  return { clients, owner, ownerClient, ownerSid: ownerSid!, passkeyId, revokedSids }
}

/**
 * Holds the first payload.db.updateOne that `matches` until release() is called. `held` resolves
 * once that write has reached the database adapter, so its read is already done.
 */
const gateUpdateOne = (matches: (data: Record<string, unknown>) => boolean) => {
  let release!: () => void
  const gate = new Promise<void>((resolve) => (release = resolve))
  let reached!: () => void
  const held = new Promise<void>((resolve) => (reached = resolve))
  let armed = true
  const updateOne = payload.db.updateOne.bind(payload.db)
  vi.spyOn(payload.db, 'updateOne').mockImplementation(async (args) => {
    if (armed && matches(args.data as Record<string, unknown>)) {
      armed = false
      reached()
      await gate
    }
    return updateOne(args)
  })
  return { held, release }
}

const within = <T>(promise: Promise<T>, ms = 5_000): Promise<T> =>
  Promise.race([
    promise,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error('timed out')), ms)),
  ])

const cookieHeader = (client: TestClient) =>
  [...client.cookies].map(([name, value]) => `${name}=${value}`).join('; ')

/** The user GraphQL's meUser sees for this client's cookies (the route isn't a REST endpoint). */
const graphqlMe = async (client: TestClient) => {
  const response = await GRAPHQL_POST(config)(
    new Request(`${SERVER_URL}/api/graphql`, {
      body: JSON.stringify({ query: '{ meUser { user { id } } }' }),
      headers: {
        Cookie: cookieHeader(client),
        'Content-Type': 'application/json',
        Origin: SERVER_URL,
      },
      method: 'POST',
    }),
  )
  const body = (await response.json()) as { data?: { meUser?: { user?: { id: unknown } | null } } }
  return body.data?.meUser?.user ?? null
}

/** Every way a revoked session could still be used. */
const expectSignedOut = async (client: TestClient, userId: number | string) => {
  expect((await client.get('/api/users/me')).json.user).toBeNull()
  expect(await graphqlMe(client)).toBeNull()
  // What the admin's server components call.
  const headers = new Headers({ Cookie: cookieHeader(client), Origin: SERVER_URL })
  expect((await payload.auth({ headers })).user).toBeNull()
  expect((await client.get(`/api/users/${userId}`)).status).not.toBe(200)
  const rename = await client.patch(`/api/users/${userId}`, {
    name: 'Renamed by a revoked session',
  })
  expect(rename.status).not.toBe(200)
  const register = await client.post('/api/users/passkeys/register/options')
  expect(register.status).toBe(401)
  expect((await client.post('/api/users/refresh-token')).status).not.toBe(200)
}

describe('a revoked session can never authenticate again (finding 1)', () => {
  it('an update that read the user before the revoke and writes after it', async () => {
    const { clients, owner, ownerClient, ownerSid, passkeyId, revokedSids } = await setUp()
    const [attacker] = clients
    const { held, release } = gateUpdateOne((data) => data.name === 'Renamed by attacker')
    const patch = attacker!.patch(`/api/users/${owner.id}`, { name: 'Renamed by attacker' })
    await within(held)

    const res = await ownerClient.post(DELETE, { id: passkeyId, signOutOtherSessions: true })
    expect(res.status).toBe(200)
    expect(res.json).toMatchObject({ removed: true, signedOutSessions: 1 })
    release()
    await patch

    // On SQLite and Postgres the held write really does put the session back. MongoDB on a replica
    // set refuses it with a write conflict (Payload's update runs in a transaction there).
    const revived = (await sessionIds(owner.id)).includes(revokedSids[0]!)
    if (payload.db.name !== 'mongoose') expect(revived).toBe(true)

    await expectSignedOut(attacker!, owner.id)
    expect((await ownerClient.get('/api/users/me')).json.user?.id).toBe(owner.id)

    // The next update through Payload drops it from the stored list as well.
    const tidy = await ownerClient.patch(`/api/users/${owner.id}`, { name: 'Owner again' })
    expect(tidy.status).toBe(200)
    expect(await sessionIds(owner.id)).toEqual([ownerSid])
  })

  it('a logout that read the user before the revoke and writes after it', async () => {
    const { clients, owner, ownerClient, ownerSid, passkeyId, revokedSids } = await setUp(2)
    const [attacker, other] = clients
    const otherSid = revokedSids[1]!
    // The other session's logout: it writes every session but its own back.
    const { held, release } = gateUpdateOne((data) => {
      const sessions = data.sessions as { id: string }[] | undefined
      return (
        Array.isArray(sessions) &&
        sessions.some((session) => session.id === ownerSid) &&
        !sessions.some((session) => session.id === otherSid) &&
        sessions.some((session) => session.id === revokedSids[0])
      )
    })
    const logout = other!.post('/api/users/logout')
    await within(held)

    const res = await ownerClient.post(DELETE, { id: passkeyId, signOutOtherSessions: true })
    expect(res.status).toBe(200)
    expect(res.json).toMatchObject({ removed: true, signedOutSessions: 2 })
    release()
    await logout

    const revived = (await sessionIds(owner.id)).includes(revokedSids[0]!)
    if (payload.db.name !== 'mongoose') expect(revived).toBe(true)

    await expectSignedOut(attacker!, owner.id)
    expect((await ownerClient.get('/api/users/me')).json.user?.id).toBe(owner.id)
  })

  it('a revoked session written straight back to the database (every adapter)', async () => {
    const { clients, owner, ownerClient, passkeyId } = await setUp()
    const [attacker] = clients
    const before = (await rawUser(payload, 'users', owner.id)).sessions ?? []
    const res = await ownerClient.post(DELETE, { id: passkeyId, signOutOtherSessions: true })
    expect(res.status).toBe(200)
    // What a lost race leaves behind, on any adapter.
    await payload.db.updateOne({
      collection: 'users',
      data: { sessions: before },
      id: owner.id,
      returning: false,
    })
    expect(await sessionIds(owner.id)).toHaveLength(2)

    await expectSignedOut(attacker!, owner.id)
    expect((await ownerClient.get('/api/users/me')).json.user?.id).toBe(owner.id)
    // The checks in expectSignedOut mean something: a live session passes them.
    expect(String((await graphqlMe(ownerClient))?.id)).toBe(String(owner.id))
    const headers = new Headers({ Cookie: cookieHeader(ownerClient), Origin: SERVER_URL })
    expect((await payload.auth({ headers })).user?.id).toBe(owner.id)
  })

  it('fails closed: no session authenticates while the revocation lookup fails', async () => {
    const { ownerClient, owner } = await setUp(0)
    expect((await ownerClient.get('/api/users/me')).json.user?.id).toBe(owner.id)
    const find = payload.db.find.bind(payload.db)
    vi.spyOn(payload.db, 'find').mockImplementation(async (args) => {
      if (args.collection === CHALLENGE_USES) throw new Error('database unavailable')
      return find(args)
    })
    expect((await ownerClient.get('/api/users/me')).json.user).toBeNull()
    vi.restoreAllMocks()
    expect((await ownerClient.get('/api/users/me')).json.user?.id).toBe(owner.id)
  })

  it('looks the sessions up in one query per read of the user', async () => {
    const { ownerClient, owner } = await setUp(2)
    const find = vi.spyOn(payload.db, 'find')
    const findOne = vi.spyOn(payload.db, 'findOne')
    await payload.findByID({ collection: 'users', id: owner.id })
    const lookups = [...find.mock.calls, ...findOne.mock.calls].filter(
      ([args]) => args.collection === CHALLENGE_USES,
    )
    expect(lookups).toHaveLength(1)
    // Nothing to look up when the document has no sessions in it.
    find.mockClear()
    findOne.mockClear()
    await payload.findByID({ collection: 'users', id: owner.id, select: { email: true } })
    const none = [...find.mock.calls, ...findOne.mock.calls].filter(
      ([args]) => args.collection === CHALLENGE_USES,
    )
    expect(none).toHaveLength(0)
    expect((await ownerClient.get('/api/users/me')).json.user?.id).toBe(owner.id)
  })
})
