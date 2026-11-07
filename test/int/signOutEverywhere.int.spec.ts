import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

import type { TestClient } from '../helpers/api.js'

import { resetPasskeys } from '../../src/server/reset.js'
import config from '../configs/single.js'
import { SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey } from '../helpers/ceremonies.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  vi.restoreAllMocks()
  await payload.destroy()
})

const DELETE = '/api/users/passkeys/delete'
const LOOPS = 4
const ROUNDS = 5
/** Each loop stops after this many refreshes or this long, whichever comes first. */
const MAX_REFRESHES = 150
const LOOP_DEADLINE_MS = 4_000

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

/** Refreshes the attacker's session in a loop until told to stop (bounded either way). */
const refreshLoop = async (client: TestClient, stop: { now: boolean }) => {
  const deadline = Date.now() + LOOP_DEADLINE_MS
  for (let i = 0; i < MAX_REFRESHES && !stop.now && Date.now() < deadline; i++) {
    await client.post('/api/users/refresh-token').catch(() => undefined)
  }
}

const passkeyExists = async (id: number | string) =>
  (await payload.count({ collection: 'passkeys', where: { id: { equals: id } } })).totalDocs === 1

/** A user with one passkey, signed in twice: the owner's browser and an attacker's. */
const setUp = async () => {
  const owner = await createUser(payload, 'users')
  const ownerClient = await passwordClient(config, 'users', owner.email)
  const { verify } = await registerPasskey(
    ownerClient,
    createSoftAuthenticator({ origin: SERVER_URL }),
  )
  const passkeyId = verify!.json.passkey.id as number | string
  const [ownerSession] = (await rawUser(payload, 'users', owner.id)).sessions ?? []
  const attacker = await passwordClient(config, 'users', owner.email)
  return { attacker, owner, ownerClient, ownerSid: ownerSession!.id, passkeyId }
}

describe('"Also sign out everywhere" under parallel refreshes (finding 1)', () => {
  it('ends the other sessions, or fails and leaves the passkey in place', async () => {
    let succeeded = 0
    for (let round = 0; round < ROUNDS; round++) {
      const { attacker, owner, ownerClient, ownerSid, passkeyId } = await setUp()
      const stop = { now: false }
      const loops = Array.from({ length: LOOPS }, () => refreshLoop(attacker, stop))
      await sleep(30)
      const res = await ownerClient.post(DELETE, { id: passkeyId, signOutOtherSessions: true })
      // Give in-flight refreshes time to land before stopping, as a real attacker's would.
      await sleep(200)
      stop.now = true
      await Promise.all(loops)

      if (res.status === 200) {
        succeeded++
        expect((await attacker.get('/api/users/me')).json.user).toBeNull()
        const sessions = (await rawUser(payload, 'users', owner.id)).sessions ?? []
        expect(sessions.map((session) => session.id)).toEqual([ownerSid])
      } else {
        expect(res.json).toEqual({ error: 'retry' })
        expect(await passkeyExists(passkeyId)).toBe(true)
      }
    }
    // Failing safe every time would be a denial of service of its own.
    expect(succeeded).toBeGreaterThan(0)
  })

  it('the reset command ends every session under parallel refreshes', async () => {
    for (let round = 0; round < ROUNDS; round++) {
      const { attacker, owner, ownerClient } = await setUp()
      const stop = { now: false }
      const loops = Array.from({ length: LOOPS }, () => refreshLoop(attacker, stop))
      await sleep(30)
      const result = await resetPasskeys({ collection: 'users', id: String(owner.id), payload })
      await sleep(200)
      stop.now = true
      await Promise.all(loops)
      expect(result.removedPasskeys).toBe(1)
      expect((await attacker.get('/api/users/me')).json.user).toBeNull()
      expect((await ownerClient.get('/api/users/me')).json.user).toBeNull()
      expect((await rawUser(payload, 'users', owner.id)).sessions ?? []).toEqual([])
    }
  })

  it('retries a write conflict and logs the retry', async () => {
    const { attacker, ownerClient, passkeyId } = await setUp()
    const warn = vi.spyOn(payload.logger, 'warn')
    const updateOne = payload.db.updateOne.bind(payload.db)
    let failed = false
    const spy = vi.spyOn(payload.db, 'updateOne').mockImplementation(async (args) => {
      if (!failed && Array.isArray((args.data as { sessions?: unknown }).sessions)) {
        failed = true
        throw Object.assign(new Error('deadlock detected'), { code: '40P01' })
      }
      return updateOne(args)
    })
    try {
      const res = await ownerClient.post(DELETE, { id: passkeyId, signOutOtherSessions: true })
      expect(res.status).toBe(200)
      expect(res.json).toMatchObject({ removed: true, signedOutSessions: 1 })
    } finally {
      spy.mockRestore()
    }
    expect(failed).toBe(true)
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ attempt: 1, msg: 'passkeys: retrying a session write' }),
    )
    expect((await attacker.get('/api/users/me')).json.user).toBeNull()
    warn.mockRestore()
  })

  it('answers 503 retry and keeps the passkey when the write keeps failing', async () => {
    const { attacker, ownerClient, passkeyId } = await setUp()
    const updateOne = payload.db.updateOne.bind(payload.db)
    const spy = vi.spyOn(payload.db, 'updateOne').mockImplementation(async (args) => {
      if (Array.isArray((args.data as { sessions?: unknown }).sessions)) {
        throw Object.assign(new Error('deadlock detected'), { code: '40P01' })
      }
      return updateOne(args)
    })
    let res
    try {
      res = await ownerClient.post(DELETE, { id: passkeyId, signOutOtherSessions: true })
    } finally {
      spy.mockRestore()
    }
    expect(res.status).toBe(503)
    expect(res.json).toEqual({ error: 'retry' })
    // Sessions are revoked before the passkey is deleted, so even without a transaction (SQLite
    // by default) a failed revoke leaves the passkey in place.
    expect(await passkeyExists(passkeyId)).toBe(true)
    expect((await ownerClient.get('/api/users/me')).json.user).not.toBeNull()
    // In a transaction (Postgres) the markers roll back with the revoke, so nothing changed.
    // Without one (SQLite by default, MongoDB) they are written first and stay, so the sessions
    // the owner asked to end can't authenticate any more: the failure errs towards signed out.
    const attackerUser = (await attacker.get('/api/users/me')).json.user
    if (payload.db.name === 'postgres') expect(attackerUser).not.toBeNull()
    else expect(attackerUser).toBeNull()
  })

  it('answers 503 sign_out_unconfirmed when the passkey went but a session outlived the check', async () => {
    const { attacker, owner, ownerClient, passkeyId } = await setUp()
    const sessionsBefore = (await rawUser(payload, 'users', owner.id)).sessions ?? []
    // Whatever the confirm loop removes comes straight back: a session it can never confirm gone.
    const updateOne = payload.db.updateOne.bind(payload.db)
    const spy = vi.spyOn(payload.db, 'updateOne').mockImplementation(async (args) => {
      const result = await updateOne(args)
      if (Array.isArray((args.data as { sessions?: unknown }).sessions)) {
        await updateOne({ ...args, data: { sessions: sessionsBefore } })
      }
      return result
    })
    let res
    try {
      res = await ownerClient.post(DELETE, { id: passkeyId, signOutOtherSessions: true })
    } finally {
      spy.mockRestore()
    }
    expect(res.status).toBe(503)
    expect(res.json).toEqual({ error: 'sign_out_unconfirmed' })
    // Not `retry`: the passkey is already gone, so retrying the removal would only find nothing.
    expect(await passkeyExists(passkeyId)).toBe(false)
    expect(
      (await ownerClient.post(DELETE, { id: passkeyId, signOutOtherSessions: true })).json,
    ).toEqual({ error: 'not_found' })
    // The sessions that came back are marked, so they can't authenticate even so.
    expect((await rawUser(payload, 'users', owner.id)).sessions?.length).toBe(2)
    expect((await attacker.get('/api/users/me')).json.user).toBeNull()
    expect((await ownerClient.get('/api/users/me')).json.user?.id).toBe(owner.id)
  })
})
