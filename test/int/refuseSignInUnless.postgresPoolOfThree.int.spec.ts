/**
 * refuseSignInUnless on Postgres with a pool of three: one held by the adapter from boot, one by
 * the sign-in's transaction, one for the hook's re-read. The smallest pool it works with
 * (refuseSignInUnless.postgresPoolOfTwo.int.spec.ts shows two isn't enough).
 */
import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { testHooks } from '../../dev/testHooks.js'
import config from '../configs/postgresPoolOfThree.js'
import { installRefusal, prepareSignIn, sessionCount } from '../helpers/signInRace.js'
import { createUser } from '../helpers/users.js'

describe.runIf(process.env.DATABASE_ADAPTER === 'postgres')(
  'refuseSignInUnless with a Postgres pool of three',
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

    it.each(['sso', 'rest-login'] as const)('lets an allowed user sign in (%s)', async (way) => {
      const user = await createUser(payload, 'users')
      const attempt = await prepareSignIn(way, config, payload, user)
      const { seen } = installRefusal({ recheckTimeoutMs: 2_000 })
      expect((await attempt.run()).ok).toBe(true)
      expect(seen).toHaveLength(2)
      expect(await sessionCount(payload, user)).toBe(1)
    })
  },
)
