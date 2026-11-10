/**
 * refuseSignInUnless on SQLite with transactions on (`transactionOptions: {}`), which
 * @payloadcms/db-sqlite leaves off by default (dist/index.js:100). With them, a disable that lands
 * while the user signs in is caught, as on MongoDB and Postgres (refuseSignInUnless.int.spec.ts).
 */
import type { Payload } from 'payload'

import { getPayload, UnauthorizedError } from 'payload'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import { testHooks } from '../../dev/testHooks.js'
import config from '../configs/sqliteTransactions.js'
import {
  disableDuringSignIn,
  installRefusal,
  LEFT,
  prepareSignIn,
  sessionCount,
  SIGN_IN_WAYS,
} from '../helpers/signInRace.js'
import { createUser, rawUser } from '../helpers/users.js'

// The option only exists on SQLite; MongoDB and Postgres run this scenario in
// refuseSignInUnless.int.spec.ts.
describe.runIf(process.env.DATABASE_ADAPTER === 'sqlite')(
  'refuseSignInUnless on SQLite with transactions',
  () => {
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

    it('runs SQLite in transactions', () => {
      expect(payload.db.name).toBe('sqlite')
      expect(
        (payload.db as unknown as { transactionOptions?: unknown }).transactionOptions,
      ).toEqual({})
    })

    it.each(SIGN_IN_WAYS)(
      'refuses a sign-in that a disable lands in, and keeps the disable (%s)',
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
        else expect(result.status).toBe(way === 'passkey' ? 400 : 401)
        expect((await rawUser(payload, 'users', user.id)).name).toBe(LEFT)
        expect(await sessionCount(payload, user)).toBe(before)
      },
    )

    it('still lets an allowed user sign in', async () => {
      const user = await createUser(payload, 'users')
      installRefusal()
      const attempt = await prepareSignIn('sso', config, payload, user)
      expect((await attempt.run()).ok).toBe(true)
      expect(await sessionCount(payload, user)).toBe(1)
    })
  },
)
