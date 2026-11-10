/**
 * refuseSignInUnless (design D3). Runs on every adapter. The suite's MongoDB is a replica set and
 * Postgres always runs transactions, so the race tests there take the "with transactions" path;
 * default SQLite runs none, so there they pin the documented limit instead. SQLite with
 * transactions is refuseSignInUnless.sqliteTransactions.int.spec.ts.
 */
import type { CollectionBeforeLoginHook, Payload, PayloadRequest } from 'payload'

import { createLocalReq, getPayload, UnauthorizedError } from 'payload'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import type { TestUser } from '../helpers/users.js'

import { testHooks } from '../../dev/testHooks.js'
import { refuseSignInUnless, signInVerifiedUser } from '../../src/index.js'
import config from '../configs/refuseSignInUnless.js'
import { findSecretKeys } from '../helpers/secrets.js'
import {
  disableDuringSignIn,
  installRefusal,
  LEFT,
  prepareSignIn,
  sessionCount,
  SIGN_IN_WAYS,
} from '../helpers/signInRace.js'
import { createUser, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})
beforeEach(() => {
  testHooks.reset()
})
afterEach(() => {
  vi.restoreAllMocks()
})

const transactional = () => process.env.DATABASE_ADAPTER !== 'sqlite'

const refusedStatus = { passkey: 400, 'rest-login': 401 } as const

/** Calls the hook as Payload would, with `user` as the record the sign-in read. */
const callHook = async (
  hook: CollectionBeforeLoginHook,
  user: Record<string, unknown>,
  req?: PayloadRequest,
) =>
  hook({
    collection: payload.collections.users!.config,
    context: {},
    req: req ?? (await createLocalReq({}, payload)),
    user: { ...user, _strategy: 'local-jwt', collection: 'users' },
  })

const storedUser = async (user: TestUser) => rawUser(payload, 'users', user.id)

describe('refuseSignInUnless: every sign-in path', () => {
  it.each(SIGN_IN_WAYS)('lets an allowed user sign in (%s)', async (way) => {
    const user = await createUser(payload, 'users')
    const attempt = await prepareSignIn(way, config, payload, user)
    const { seen } = installRefusal()
    const before = await sessionCount(payload, user)
    const result = await attempt.run()
    expect(result).toMatchObject({ ok: true })
    expect(await sessionCount(payload, user)).toBe(before + 1)
    // Once with the record the sign-in read, once with the stored record.
    expect(seen).toHaveLength(2)
  })

  it.each(SIGN_IN_WAYS)('refuses a disallowed user, adding no session (%s)', async (way) => {
    const user = await createUser(payload, 'users')
    const attempt = await prepareSignIn(way, config, payload, user)
    await payload.db.updateOne({
      collection: 'users',
      data: { name: LEFT },
      id: user.id,
      returning: false,
    })
    installRefusal()
    const before = await sessionCount(payload, user)
    const result = await attempt.run()
    expect(result.ok).toBe(false)
    if (way === 'sso') expect(result.error).toBeInstanceOf(UnauthorizedError)
    else expect(result.status).toBe(refusedStatus[way])
    expect(await sessionCount(payload, user)).toBe(before)
  })
})

describe('refuseSignInUnless: the stored record decides', () => {
  it('refuses when the hook is handed an allowed user but the stored record is disallowed', async () => {
    const user = await createUser(payload, 'users')
    const stale = await storedUser(user)
    await payload.db.updateOne({
      collection: 'users',
      data: { name: LEFT },
      id: user.id,
      returning: false,
    })
    const calls: string[] = []
    const hook = refuseSignInUnless((u) => {
      calls.push(String(u.name))
      return u.name !== LEFT
    })
    await expect(callHook(hook, stale)).rejects.toBeInstanceOf(UnauthorizedError)
    expect(calls).toEqual(['Test User', LEFT])
  })

  it('returns the user it was given when both reads are allowed', async () => {
    const user = await createUser(payload, 'users')
    const stored = await storedUser(user)
    const hook = refuseSignInUnless(() => true)
    const result = (await callHook(hook, stored)) as Record<string, unknown>
    expect(result).toMatchObject({ _strategy: 'local-jwt', collection: 'users', id: user.id })
    expect(result.hash).toBe(stored.hash)
  })

  it('clears its own timer when the re-read wins', async () => {
    const user = await createUser(payload, 'users')
    const stored = await storedUser(user)
    // An unusual delay picks out the hook's timer from any other setTimeout made meanwhile.
    const recheckTimeoutMs = 4_321
    const set = vi.spyOn(globalThis, 'setTimeout')
    const clear = vi.spyOn(globalThis, 'clearTimeout')
    await callHook(
      refuseSignInUnless(() => true, { recheckTimeoutMs }),
      stored,
    )
    const index = set.mock.calls.findIndex(([, delay]) => delay === recheckTimeoutMs)
    expect(index).toBeGreaterThanOrEqual(0)
    expect(clear).toHaveBeenCalledWith(set.mock.results[index]!.value)
    set.mockRestore()
    clear.mockRestore()
  })

  it('refuses a soft-deleted user (trash on)', async () => {
    const user = await createUser(payload, 'users')
    const stored = await storedUser(user)
    await payload.db.updateOne({
      collection: 'users',
      data: { deletedAt: new Date().toISOString() },
      id: user.id,
      returning: false,
    })
    // The adapter still returns the trashed record without a filter: the hook must add it.
    expect((await storedUser(user))?.deletedAt).toBeTruthy()
    const predicate = vi.fn(() => true)
    await expect(callHook(refuseSignInUnless(predicate), stored)).rejects.toBeInstanceOf(
      UnauthorizedError,
    )
    expect(predicate).toHaveBeenCalledTimes(1)
  })

  it('refuses a user that no longer exists', async () => {
    const user = await createUser(payload, 'users')
    const stored = await storedUser(user)
    await payload.db.deleteOne({ collection: 'users', where: { id: { equals: user.id } } })
    await expect(
      callHook(
        refuseSignInUnless(() => true),
        stored,
      ),
    ).rejects.toBeInstanceOf(UnauthorizedError)
  })

  it('refuses anything but true', async () => {
    const user = await createUser(payload, 'users')
    const stored = await storedUser(user)
    const sloppy = (() => 'yes') as unknown as () => boolean
    await expect(callHook(refuseSignInUnless(sloppy), stored)).rejects.toBeInstanceOf(
      UnauthorizedError,
    )
  })
})

describe('refuseSignInUnless: what the predicate sees', () => {
  it('never receives hash, salt, sessions or another secret, on either call', async () => {
    const user = await createUser(payload, 'users')
    const { seen } = installRefusal()
    await signInVerifiedUser({ collection: 'users', payload, userId: user.id })
    // A REST login too: Payload's login hands the hook its own (sanitised) record.
    const attempt = await prepareSignIn('rest-login', config, payload, user)
    expect((await attempt.run()).ok).toBe(true)
    expect(seen).toHaveLength(4)
    for (const arg of seen) {
      expect(findSecretKeys(arg)).toEqual([])
      for (const key of ['hash', 'salt', 'sessions', 'loginAttempts', 'lockUntil']) {
        expect(arg).not.toHaveProperty(key)
      }
      expect(arg).toMatchObject({ collection: 'users', email: user.email, id: user.id })
      expect(arg).not.toHaveProperty('_strategy')
      expect(arg).not.toHaveProperty('_sid')
    }
    // The same shape both times, but for updatedAt: addSessionToUser sets it to null on the
    // sign-in's copy (payload/dist/auth/sessions.js), and an adapter may drop the null key.
    const keys = (arg: Record<string, unknown>) =>
      Object.keys(arg)
        .filter((key) => key !== 'updatedAt')
        .sort()
    expect(keys(seen[0]!)).toEqual(keys(seen[1]!))
    expect(keys(seen[2]!)).toEqual(keys(seen[3]!))
  })
})

describe('refuseSignInUnless: fails closed', () => {
  it('refuses when the predicate throws, adding no session', async () => {
    const user = await createUser(payload, 'users')
    installRefusal({
      isAllowed: () => {
        throw new Error('directory unavailable')
      },
    })
    await expect(
      signInVerifiedUser({ collection: 'users', payload, userId: user.id }),
    ).rejects.toThrow('directory unavailable')
    expect(await sessionCount(payload, user)).toBe(0)
  })

  it('refuses when the re-read throws, adding no session', async () => {
    const user = await createUser(payload, 'users')
    installRefusal()
    const findOne = payload.db.findOne.bind(payload.db)
    let thrown = 0
    const spy = vi.spyOn(payload.db, 'findOne').mockImplementation(async (args) => {
      // Only the hook's re-read runs without req: the sign-in's own reads carry it.
      if (!args.req && args.collection === 'users') {
        thrown++
        throw new Error('database unavailable')
      }
      return findOne(args)
    })
    await expect(
      signInVerifiedUser({ collection: 'users', payload, userId: user.id }),
    ).rejects.toThrow('database unavailable')
    spy.mockRestore()
    expect(thrown).toBe(1)
    expect(await sessionCount(payload, user)).toBe(0)
  })

  it('refuses when the re-read takes longer than recheckTimeoutMs', async () => {
    const user = await createUser(payload, 'users')
    const stored = await storedUser(user)
    const findOne = payload.db.findOne.bind(payload.db)
    let release!: () => void
    const held = new Promise<void>((resolve) => (release = resolve))
    vi.spyOn(payload.db, 'findOne').mockImplementation(async (args) => {
      if (!args.req) await held
      return findOne(args)
    })
    const error = vi.spyOn(payload.logger, 'error').mockImplementation(() => undefined)
    const started = Date.now()
    await expect(
      callHook(
        refuseSignInUnless(() => true, { recheckTimeoutMs: 200 }),
        stored,
      ),
    ).rejects.toBeInstanceOf(UnauthorizedError)
    expect(Date.now() - started).toBeLessThan(2_000)
    expect(error).toHaveBeenCalledWith(
      expect.objectContaining({ collection: 'users', userId: user.id }),
    )
    release()
  })
})

describe('refuseSignInUnless: a disable that lands while the user signs in', () => {
  it.runIf(transactional()).each(SIGN_IN_WAYS)(
    'with transactions, refuses it and keeps the disable (%s)',
    async (way) => {
      const user = await createUser(payload, 'users')
      const attempt = await prepareSignIn(way, config, payload, user)
      const { seen } = installRefusal()
      const before = await sessionCount(payload, user)
      const seam = disableDuringSignIn(payload, user)
      const result = await attempt.run()
      seam.restore()
      expect(seam.fired).toBe(true)
      // The sign-in read the user before the disable; the re-read is what refused.
      expect(seen.map((u) => u.name)).toEqual(['Test User', LEFT])
      expect(result.ok).toBe(false)
      if (way === 'sso') expect(result.error).toBeInstanceOf(UnauthorizedError)
      else expect(result.status).toBe(refusedStatus[way])
      expect((await storedUser(user)).name).toBe(LEFT)
      expect(await sessionCount(payload, user)).toBe(before)
    },
  )

  // Default SQLite runs no transactions (@payloadcms/db-sqlite dist/index.js:100): the stale
  // whole-record write in addSessionToUser has committed before beforeLogin runs, so the re-read
  // sees it. This pins the limit the README documents.
  it.runIf(!transactional()).each(SIGN_IN_WAYS)(
    'without transactions, cannot catch it: the sign-in succeeds and the stale record is stored (%s)',
    async (way) => {
      const user = await createUser(payload, 'users')
      const attempt = await prepareSignIn(way, config, payload, user)
      const { seen } = installRefusal()
      const before = await sessionCount(payload, user)
      const seam = disableDuringSignIn(payload, user)
      const result = await attempt.run()
      seam.restore()
      expect(seam.fired).toBe(true)
      // Both calls see the stale name: the stale write committed before the hook ran.
      expect(seen.map((u) => u.name)).toEqual(['Test User', 'Test User'])
      expect(result.ok).toBe(true)
      expect((await storedUser(user)).name).toBe('Test User')
      expect(await sessionCount(payload, user)).toBe(before + 1)
    },
  )
})
