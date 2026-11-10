/**
 * refuseSignInUnless on Postgres when the pool has no connection to spare. The plan said a pool of
 * one, but @payloadcms/db-postgres 3.90.2 holds one connection for good from boot (dist/connect.js:
 * connectWithReconnect calls pool.connect() and never releases it), so a pool of one can't boot.
 * With two, the sign-in's transaction holds the only free one and the hook's re-read (no req, so
 * outside the transaction) waits for another, which pg-pool would wait for for ever
 * (`connectionTimeoutMillis` defaults to 0). recheckTimeoutMs must refuse instead of hanging.
 */
import type { Payload } from 'payload'

import { getPayload, UnauthorizedError } from 'payload'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import { testHooks } from '../../dev/testHooks.js'
import config from '../configs/postgresPoolOfTwo.js'
import { installRefusal, prepareSignIn, sessionCount } from '../helpers/signInRace.js'
import { createUser } from '../helpers/users.js'

const RECHECK_TIMEOUT_MS = 300

type Pool = { options: { max?: number }; totalCount: number; waitingCount: number }

// Only Postgres pools connections per transaction: MongoDB and libsql are unaffected.
describe.runIf(process.env.DATABASE_ADAPTER === 'postgres')(
  'refuseSignInUnless with a Postgres pool of two',
  () => {
    let payload: Payload
    beforeAll(async () => {
      payload = await getPayload({ config })
    })
    afterAll(async () => {
      // Let the queued re-reads have the connection back before the pool closes.
      const pool = (payload.db as unknown as { pool: Pool }).pool
      for (let i = 0; i < 50 && pool.waitingCount > 0; i++) {
        await new Promise((resolve) => setTimeout(resolve, 100))
      }
      await payload.destroy()
    })
    beforeEach(() => {
      testHooks.reset()
    })
    afterEach(() => {
      vi.restoreAllMocks()
    })

    it('runs with a pool of two', () => {
      expect((payload.db as unknown as { pool: Pool }).pool.options.max).toBe(2)
    })

    it.each(['sso', 'rest-login'] as const)(
      'refuses within recheckTimeoutMs instead of hanging (%s)',
      async (way) => {
        const user = await createUser(payload, 'users')
        const attempt = await prepareSignIn(way, config, payload, user)
        installRefusal({ recheckTimeoutMs: RECHECK_TIMEOUT_MS })
        const logged = vi.spyOn(payload.logger, 'error')
        const started = Date.now()
        const result = await attempt.run()
        expect(Date.now() - started).toBeLessThan(RECHECK_TIMEOUT_MS + 5_000)
        expect(result.ok).toBe(false)
        if (way === 'sso') expect(result.error).toBeInstanceOf(UnauthorizedError)
        else expect(result.status).toBe(401)
        expect(logged).toHaveBeenCalledWith(
          expect.objectContaining({ collection: 'users', userId: user.id }),
        )
        expect(await sessionCount(payload, user)).toBe(0)
      },
    )
  },
)
