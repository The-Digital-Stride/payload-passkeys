/**
 * revokeSessions reads the stored user, filters its sessions and writes them back. The write must
 * carry the sessions only (and what the database adapter would otherwise lose), never a stale copy
 * of the rest of the user: a password change that lands between the read and the write has to
 * survive. A users collection of its own, with an array, a blocks field and a hasMany select,
 * because Postgres and SQLite delete the rows of any array or blocks field an update leaves out.
 */
import type { Payload } from 'payload'

import { buildConfig, getPayload } from 'payload'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'

import { databaseAdapter } from '../../dev/db.js'
import { revokeSessions } from '../../src/server/mintSession.js'
import { requestFor } from '../helpers/requests.js'
import { PASSWORD, rawUser } from '../helpers/users.js'

const NEW_PASSWORD = 'a brand new password for this test'

const config = buildConfig({
  collections: [
    {
      slug: 'users',
      auth: true,
      fields: [
        { name: 'name', type: 'text' },
        { name: 'tags', type: 'array', fields: [{ name: 'label', type: 'text' }] },
        {
          name: 'content',
          type: 'blocks',
          blocks: [{ slug: 'note', fields: [{ name: 'body', type: 'text' }] }],
        },
        { name: 'roles', type: 'select', hasMany: true, options: ['editor', 'author'] },
      ],
    },
  ],
  db: databaseAdapter(),
  secret: process.env.PAYLOAD_SECRET ?? 'integration-test-secret-not-for-production',
  typescript: { autoGenerate: false },
})

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

let count = 0

/** A user with every kind of field and `sessions` signed-in sessions. */
const signedInUser = async (sessions = 2) => {
  const email = `revoke-${++count}-${Date.now()}@example.test`
  const doc = await payload.create({
    collection: 'users',
    data: {
      content: [{ blockType: 'note', body: 'Kept' }],
      email,
      name: 'Before',
      password: PASSWORD,
      roles: ['editor', 'author'],
      tags: [{ label: 'first' }, { label: 'second' }],
    } as never,
  })
  for (let i = 0; i < sessions; i++) {
    await payload.login({ collection: 'users', data: { email, password: PASSWORD } })
  }
  const sids = (await rawUser(payload, 'users', doc.id)).sessions!.map((s) => s.id)
  expect(sids).toHaveLength(sessions)
  return { email, id: doc.id, sids }
}

const revoke = async (userId: number | string, only: string[]) =>
  revokeSessions({
    collectionSlug: 'users',
    only,
    req: await requestFor(config, '/api/users/passkeys/delete'),
    userId,
  })

const canLogIn = (email: string, password: string) =>
  payload.login({ collection: 'users', data: { email, password } }).then(
    () => true,
    () => false,
  )

const withoutSessions = ({ sessions: _sessions, ...rest }: Record<string, unknown>) => rest

describe('revokeSessions writes only the sessions', () => {
  it('keeps a password change that lands between its read and its write', async () => {
    const { email, id, sids } = await signedInUser()
    const findOne = payload.db.findOne.bind(payload.db)
    let armed = true
    vi.spyOn(payload.db, 'findOne').mockImplementation(async (args) => {
      const result = await findOne(args)
      if (armed && args.collection === 'users') {
        armed = false
        await payload.update({
          collection: 'users',
          data: { name: 'Changed meanwhile', password: NEW_PASSWORD },
          id,
        })
      }
      return result
    })

    expect(await revoke(id, [sids[0]!])).toBe(1)
    expect(armed).toBe(false)
    vi.restoreAllMocks()

    const stored = await rawUser(payload, 'users', id)
    expect(stored.sessions?.map((s) => s.id)).not.toContain(sids[0])
    expect(stored.name).toBe('Changed meanwhile')
    expect(await canLogIn(email, PASSWORD)).toBe(false)
    expect(await canLogIn(email, NEW_PASSWORD)).toBe(true)
  })

  it('leaves every other field as it was, arrays and blocks included', async () => {
    const { id, sids } = await signedInUser(3)
    const before = await rawUser(payload, 'users', id)

    expect(await revoke(id, [sids[1]!])).toBe(1)
    const after = await rawUser(payload, 'users', id)
    expect(after.sessions?.map((s) => s.id)).toEqual([sids[0], sids[2]])
    expect(withoutSessions(after)).toEqual(withoutSessions(before))

    expect(await revoke(id, [sids[0]!, sids[2]!])).toBe(2)
    const emptied = await rawUser(payload, 'users', id)
    expect(emptied.sessions ?? []).toHaveLength(0)
    expect(withoutSessions(emptied)).toEqual(withoutSessions(before))
  })
})
