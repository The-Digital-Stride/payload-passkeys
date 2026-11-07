/**
 * revokeSessions reads the stored user, filters its sessions and writes them back (design section
 * 13, item 19). It must never lose or undo a host's data:
 * - MongoDB: it removes the sessions with one atomic $pull, so a write landing between its read
 *   and its write stays, and a session that write ended is never written back.
 * - Postgres and SQLite: it locks the user's row first, then re-reads and writes the whole user,
 *   the shape core's logout writes. In a transaction (Postgres) a racing write waits for the revoke
 *   to commit; without one (SQLite's default) the race is core's logout's (section 12).
 * The users collection has every field shape that lives outside the main row on Drizzle (arrays,
 * blocks, hasMany selects, localized fields, in groups and tabs), and a second suite stores blocks
 * as JSON on the main row (`blocksAsJSON`).
 */
import type { Block, CollectionConfig, Payload, PayloadRequest } from 'payload'

import { buildConfig, createPayloadRequest, getPayload } from 'payload'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'

import { adapterName, databaseAdapter } from '../../dev/db.js'
import { userHandleField } from '../../src/collections/userFields.js'
import { revokeSessions } from '../../src/server/mintSession.js'
import { runSessionWrite } from '../../src/server/sessions.js'
import { USER_HANDLE_FIELD } from '../../src/shared/constants.js'
import { createClient, SERVER_URL } from '../helpers/api.js'
import { PASSWORD, rawUser } from '../helpers/users.js'

const NEW_PASSWORD = 'a brand new password for this test'
const SECRET = process.env.PAYLOAD_SECRET ?? 'integration-test-secret-not-for-production'

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

const note: Block = { slug: 'note', fields: [{ name: 'body', type: 'text' }] }

/** Every top-level field shape, and the same shapes again in a group, a named tab and a plain tab. */
const users: CollectionConfig = {
  slug: 'users',
  auth: true,
  fields: [
    userHandleField,
    { name: 'name', type: 'text' },
    { name: 'title', type: 'text', localized: true },
    { name: 'tags', type: 'array', fields: [{ name: 'label', type: 'text' }] },
    {
      name: 'localizedTags',
      type: 'array',
      fields: [{ name: 'label', type: 'text' }],
      localized: true,
    },
    { name: 'content', type: 'blocks', blocks: [note] },
    { name: 'roles', type: 'select', hasMany: true, options: ['editor', 'author'] },
    {
      name: 'meta',
      type: 'group',
      fields: [
        // Shares the `note` slug (and so, on Drizzle, the blocks table) with `content`.
        { name: 'extra', type: 'blocks', blocks: [note] },
        { name: 'links', type: 'array', fields: [{ name: 'url', type: 'text' }] },
      ],
    },
    {
      type: 'tabs',
      tabs: [
        {
          name: 'profile',
          fields: [
            { name: 'sections', type: 'blocks', blocks: [note] },
            { name: 'items', type: 'array', fields: [{ name: 'label', type: 'text' }] },
          ],
        },
        {
          fields: [
            { name: 'more', type: 'array', fields: [{ name: 'label', type: 'text' }] },
            { name: 'bio', type: 'text', localized: true },
          ],
          label: 'Other',
        },
      ],
    },
  ],
}

const configFor = (blocksAsJSON: boolean) =>
  buildConfig({
    collections: [users],
    db: databaseAdapter({ blocksAsJSON }),
    localization: { defaultLocale: 'en', locales: ['en', 'fr'] },
    secret: SECRET,
    typescript: { autoGenerate: false },
  })

const relational = configFor(false)
type TestConfig = typeof relational

/** A request to the given Payload instance (`key`: its getPayload cache key). */
const requestTo = (config: TestConfig, key?: string) =>
  createPayloadRequest({
    config,
    payloadInstanceCacheKey: key,
    request: new Request(`${SERVER_URL}/api/users/passkeys/delete`, { method: 'POST' }),
  })

afterEach(() => {
  vi.restoreAllMocks()
})

let count = 0

/** A user with every kind of field filled in (both locales) and `sessions` signed-in sessions. */
const signedInUser = async (payload: Payload, { handle = true, sessions = 2 } = {}) => {
  const email = `revoke-${++count}-${Date.now()}@example.test`
  const doc = await payload.create({
    collection: 'users',
    data: {
      ...(handle ? { [USER_HANDLE_FIELD]: `handle-${count}` } : {}),
      bio: 'Bio',
      content: [{ blockType: 'note', body: 'Top level' }],
      email,
      localizedTags: [{ label: 'english' }],
      meta: {
        extra: [{ blockType: 'note', body: 'Nested in a group' }],
        links: [{ url: 'https://example.test' }],
      },
      more: [{ label: 'unnamed tab' }],
      name: 'Before',
      password: PASSWORD,
      profile: {
        items: [{ label: 'named tab' }],
        sections: [{ blockType: 'note', body: 'Nested in a tab' }],
      },
      roles: ['editor', 'author'],
      tags: [{ label: 'first' }, { label: 'second' }],
      title: 'English title',
    } as never,
    locale: 'en',
  })
  await payload.update({
    collection: 'users',
    data: { bio: 'Biographie', localizedTags: [{ label: 'français' }], title: 'Titre' } as never,
    id: doc.id,
    locale: 'fr',
  })
  const tokens = new Map<string, string>()
  for (let i = 0; i < sessions; i++) {
    const { token } = await payload.login({
      collection: 'users',
      data: { email, password: PASSWORD },
    })
    tokens.set(sidOf(token!), token!)
  }
  const stored = await rawUser(payload, 'users', doc.id)
  if (handle) expect(stored[USER_HANDLE_FIELD]).toBe(`handle-${count}`)
  const sids = stored.sessions!.map((s) => s.id)
  expect(sids).toHaveLength(sessions)
  expect([...tokens.keys()].sort()).toEqual([...sids].sort())
  return { email, id: doc.id, sids, tokens }
}

const sidOf = (token: string): string =>
  (JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString('utf8')) as { sid: string })
    .sid

/** The user /api/users/me returns for this token (over Payload's REST stack), or null. */
const meWith = async (config: TestConfig, token: string | undefined) =>
  ((await createClient(config).get('/api/users/me', { headers: { Authorization: `JWT ${token}` } }))
    .json?.user ?? null) as null | { id: number | string }

/**
 * A password change from a separate request, as the user signed in as `sid`: Payload ends every
 * other session (update.js keeps only the caller's).
 */
const changePasswordAs = async (payload: Payload, id: number | string, sid: string) => {
  const self = await payload.findByID({ collection: 'users', depth: 0, id })
  return payload.update({
    collection: 'users',
    data: { name: 'Changed meanwhile', password: NEW_PASSWORD } as never,
    id,
    user: { ...self, _sid: sid, collection: 'users' } as never,
  })
}

/**
 * Revokes as the plugin does: through runSessionWrite, in a transaction where there is one.
 * An array revokes those sids (`only`); a string keeps that sid alone (`keep`).
 */
const revoke = (req: PayloadRequest, userId: number | string, which: string | string[]) =>
  runSessionWrite({
    label: 'test revoke',
    req,
    work: () =>
      revokeSessions({
        collectionSlug: 'users',
        ...(typeof which === 'string' ? { keep: which } : { only: which }),
        req,
        userId,
      }),
  })

const canLogIn = (payload: Payload, email: string, password: string) =>
  payload.login({ collection: 'users', data: { email, password } }).then(
    () => true,
    () => false,
  )

const withoutSessions = ({ sessions: _sessions, ...rest }: Record<string, unknown>) => rest

/** The user in both locales, through the Local API, without sessions. */
const localized = async (payload: Payload, id: number | string) => {
  const read = async (locale: 'en' | 'fr') =>
    withoutSessions(
      (await payload.findByID({ collection: 'users', depth: 0, id, locale })) as Record<
        string,
        unknown
      >,
    )
  return { en: await read('en'), fr: await read('fr') }
}

describe('revokeSessions on relational blocks', () => {
  let payload: Payload
  beforeAll(async () => {
    payload = await getPayload({ config: relational })
  })
  afterAll(async () => {
    await payload.destroy()
  })

  it('never undoes a password change that lands between its read and its write, but on Drizzle without transactions', async () => {
    const adapter = adapterName()
    const { email, id, sids, tokens } = await signedInUser(payload)
    const req = await requestTo(relational)

    // The racing update runs in its own request (and transaction). It ends every session.
    let racing: Promise<unknown> | undefined
    let raceDoneAt = 0
    let written: unknown
    const race = () =>
      (racing = payload
        .update({
          collection: 'users',
          data: { name: 'Changed meanwhile', password: NEW_PASSWORD },
          id,
        })
        .then(() => {
          raceDoneAt = Date.now()
        }))
    if (adapter === 'mongo') {
      // MongoDB takes no lock: the update commits between the revoke's read and its write.
      const findOne = payload.db.findOne.bind(payload.db)
      vi.spyOn(payload.db, 'findOne').mockImplementation(async (args) => {
        const found = await findOne(args)
        if (args.req === req && !racing) await race()
        return found
      })
    } else {
      // On Drizzle it is injected just before the session write, after the row lock.
      const updateOne = payload.db.updateOne.bind(payload.db)
      vi.spyOn(payload.db, 'updateOne').mockImplementation(async (args) => {
        if (args.req === req && args.data && 'sessions' in args.data && !racing) {
          written = args.data.sessions
          void race()
          if (adapter === 'postgres') {
            // It has to wait for the revoke's row lock: it can't commit before the revoke does.
            await sleep(500)
            expect(raceDoneAt).toBe(0)
          } else {
            await racing
          }
        }
        return updateOne(args)
      })
    }

    // On MongoDB the password change had already ended the session, so there was none to remove.
    expect(await revoke(req, id, [sids[0]!])).toBe(adapter === 'mongo' ? 0 : 1)
    const committedAt = Date.now()
    expect(racing).toBeDefined()
    await racing
    vi.restoreAllMocks()
    if (adapter !== 'mongo') {
      expect((written as { id: string }[]).map((s) => s.id)).toEqual([sids[1]])
    }

    const stored = await rawUser(payload, 'users', id)
    if (adapter === 'sqlite') {
      // Without a transaction (SQLite's default) the row lock ends with its statement, and the
      // whole-user write restores what it read, as Payload's own logout and refresh do. Accepted
      // risk, design section 12 ("A racing refresh or logout can undo a password change").
      expect(stored.name).toBe('Before')
      expect(await canLogIn(payload, email, PASSWORD)).toBe(true)
      expect(await canLogIn(payload, email, NEW_PASSWORD)).toBe(false)
      return
    }
    expect(stored.name).toBe('Changed meanwhile')
    expect(await canLogIn(payload, email, PASSWORD)).toBe(false)
    expect(await canLogIn(payload, email, NEW_PASSWORD)).toBe(true)
    if (adapter === 'postgres') {
      // It waited for the commit, then wrote the sessions it had read before the revoke: the
      // revived session is the markers' job (design section 13, item 18).
      expect(raceDoneAt).toBeGreaterThanOrEqual(committedAt)
    } else {
      // The $pull removed only what it matched: the session the password change ended stays gone.
      expect(stored.sessions ?? []).toEqual([])
      expect(await meWith(relational, tokens.get(sids[1]!))).toBeNull()
    }
  })

  it('never writes back a session a racing password change ended (only, keep)', async () => {
    for (const mode of ['only', 'keep'] as const) {
      const { id, sids, tokens } = await signedInUser(payload, { sessions: 3 })
      const [s0, s1, s2] = sids as [string, string, string]
      const req = await requestTo(relational)

      // Between the revoke's (first) read and its write, a password change signed in as s2 ends
      // s0 and s1. On Drizzle this lands before the row lock, and the re-read after it sees it.
      let raced = false
      const findOne = payload.db.findOne.bind(payload.db)
      vi.spyOn(payload.db, 'findOne').mockImplementation(async (args) => {
        const found = await findOne(args)
        if (args.req === req && !raced) {
          raced = true
          await changePasswordAs(payload, id, s2)
        }
        return found
      })

      await revoke(req, id, mode === 'only' ? [s0] : s1)
      vi.restoreAllMocks()
      expect(raced).toBe(true)

      const stored = await rawUser(payload, 'users', id)
      expect(stored.sessions?.map((s) => s.id) ?? []).toEqual(mode === 'only' ? [s2] : [])
      expect(stored.name).toBe('Changed meanwhile')
      expect(await meWith(relational, tokens.get(s0))).toBeNull()
      expect(await meWith(relational, tokens.get(s1))).toBeNull()
      if (mode === 'only') expect((await meWith(relational, tokens.get(s2)))?.id).toBe(id)
    }
  })

  it.skipIf(adapterName() === 'mongo')(
    're-reads the user after the row lock, so a write that committed before it stays',
    async () => {
      const { email, id, sids } = await signedInUser(payload)
      const req = await requestTo(relational)

      // The racing change commits after the revoke's first read but before its lock (the handle
      // write); keeping only s1, it leaves exactly one session for the revoke to remove.
      let raced = false
      const updateOne = payload.db.updateOne.bind(payload.db)
      vi.spyOn(payload.db, 'updateOne').mockImplementation(async (args) => {
        if (args.req === req && args.data && USER_HANDLE_FIELD in args.data && !raced) {
          expect('sessions' in args.data).toBe(false)
          raced = true
          await changePasswordAs(payload, id, sids[1]!)
        }
        return updateOne(args)
      })

      expect(await revoke(req, id, [sids[1]!])).toBe(1)
      vi.restoreAllMocks()
      expect(raced).toBe(true)

      const stored = await rawUser(payload, 'users', id)
      expect(stored.sessions ?? []).toEqual([])
      expect(stored.name).toBe('Changed meanwhile')
      expect(await canLogIn(payload, email, PASSWORD)).toBe(false)
      expect(await canLogIn(payload, email, NEW_PASSWORD)).toBe(true)
    },
  )

  it('leaves every other field as it was, in every locale, with and without a user handle', async () => {
    for (const handle of [true, false]) {
      const { id, sids } = await signedInUser(payload, { handle, sessions: 3 })
      const before = await rawUser(payload, 'users', id)
      const beforeLocalized = await localized(payload, id)

      expect(await revoke(await requestTo(relational), id, [sids[1]!])).toBe(1)
      const after = await rawUser(payload, 'users', id)
      expect(after.sessions?.map((s) => s.id)).toEqual([sids[0], sids[2]])
      expect(withoutSessions(after)).toEqual(withoutSessions(before))
      expect(await localized(payload, id)).toEqual(beforeLocalized)

      expect(await revoke(await requestTo(relational), id, [sids[0]!, sids[2]!])).toBe(2)
      const emptied = await rawUser(payload, 'users', id)
      expect(emptied.sessions ?? []).toHaveLength(0)
      expect(withoutSessions(emptied)).toEqual(withoutSessions(before))
      expect(await localized(payload, id)).toEqual(beforeLocalized)
    }
  })

  it('keeps blocks nested in a group that share a slug with a top-level blocks field', async () => {
    const { id, sids } = await signedInUser(payload)

    expect(await revoke(await requestTo(relational), id, [sids[0]!])).toBe(1)
    const after = (await payload.findByID({ collection: 'users', depth: 0, id })) as Record<
      string,
      unknown
    > & { meta?: { extra?: { blockType: string; body: string }[] } }
    expect(after.meta?.extra?.map(({ blockType, body }) => ({ blockType, body }))).toEqual([
      { blockType: 'note', body: 'Nested in a group' },
    ])
  })
})

describe('revokeSessions with blocks stored as JSON (blocksAsJSON)', () => {
  const asJSON = configFor(true)
  const KEY = 'blocks-as-json'
  let payload: Payload
  beforeAll(async () => {
    payload = await getPayload({ config: asJSON, key: KEY })
  })
  afterAll(async () => {
    await payload.destroy()
  })

  it('removes the session and leaves every other field as it was', async () => {
    const { id, sids } = await signedInUser(payload)
    const before = await rawUser(payload, 'users', id)
    const beforeLocalized = await localized(payload, id)

    expect(await revoke(await requestTo(asJSON, KEY), id, [sids[0]!])).toBe(1)
    const after = await rawUser(payload, 'users', id)
    expect(after.sessions?.map((s) => s.id)).toEqual([sids[1]])
    expect(withoutSessions(after)).toEqual(withoutSessions(before))
    expect(await localized(payload, id)).toEqual(beforeLocalized)
  })
})
