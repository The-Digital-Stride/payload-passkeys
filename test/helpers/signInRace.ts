import type { Payload, SanitizedConfig } from 'payload'

import { vi } from 'vitest'

import type { SignInAllowed } from '../../src/types.js'
import type { TestUser } from './users.js'

import { testHooks } from '../../dev/testHooks.js'
import { refuseSignInUnless, signInVerifiedUser } from '../../src/index.js'
import { createClient, SERVER_URL } from './api.js'
import { passwordClient, registerPasskey, signInWithPasskey } from './ceremonies.js'
import { createSoftAuthenticator } from './softAuthenticator.js'
import { PASSWORD, rawUser } from './users.js'

/** The name that marks a user as having left: the predicate refuses it. */
export const LEFT = 'Left'

/**
 * Installs refuseSignInUnless as the users collection's beforeLogin hook (through testHooks),
 * refusing anyone named LEFT. `seen` collects every argument the predicate receives.
 */
export const installRefusal = (
  options: { isAllowed?: SignInAllowed; recheckTimeoutMs?: number } = {},
) => {
  const seen: Record<string, unknown>[] = []
  const isAllowed: SignInAllowed = options.isAllowed ?? ((user) => user.name !== LEFT)
  const hook = refuseSignInUnless(
    (user) => {
      seen.push(user)
      return isAllowed(user)
    },
    options.recheckTimeoutMs === undefined ? {} : { recheckTimeoutMs: options.recheckTimeoutMs },
  )
  testHooks.beforeLogin = (args) => hook(args as never)
  return { seen }
}

/**
 * The race seam. On the sign-in's first read of the user that carries `req` (Payload's login reads
 * by email, mintSession by id), it reads the user as stored, then commits `name: LEFT` without
 * `req`, then hands back the stale read. That puts the disable after the sign-in's first read and
 * before its transaction starts, so addSessionToUser writes the stale record back.
 */
export const disableDuringSignIn = (payload: Payload, user: TestUser) => {
  const findOne = payload.db.findOne.bind(payload.db)
  let armed = true
  const spy = vi.spyOn(payload.db, 'findOne').mockImplementation(async (args) => {
    const where = JSON.stringify(args.where ?? {})
    if (
      armed &&
      args.req &&
      args.collection === user.collection &&
      (where.includes(JSON.stringify(user.email)) || where.includes(JSON.stringify(user.id)))
    ) {
      armed = false
      const stale = await findOne(args)
      await payload.db.updateOne({
        collection: user.collection,
        data: { name: LEFT },
        id: user.id,
        returning: false,
      })
      return stale
    }
    return findOne(args)
  })
  return {
    restore: () => spy.mockRestore(),
    /** Whether the disable was written. */
    get fired() {
      return !armed
    },
  }
}

export type SignInWay = 'passkey' | 'rest-login' | 'sso'

export type SignInAttempt = {
  /** Runs the sign-in. `ok` is whether it signed the user in. */
  run: () => Promise<{ error?: unknown; ok: boolean; status?: number }>
}

/**
 * Sets up one way of signing `user` in. For a passkey sign-in it registers a passkey first (which
 * signs the user in with the password once), so count sessions after this, not before.
 */
export const prepareSignIn = async (
  way: SignInWay,
  config: Promise<SanitizedConfig>,
  payload: Payload,
  user: TestUser,
): Promise<SignInAttempt> => {
  switch (way) {
    case 'passkey': {
      const authenticator = createSoftAuthenticator({ origin: SERVER_URL })
      const { verify } = await registerPasskey(
        await passwordClient(config, user.collection, user.email),
        authenticator,
        { collection: user.collection },
      )
      if (verify?.status !== 200) throw new Error(`passkey registration failed: ${verify?.status}`)
      return {
        run: async () => {
          const result = await signInWithPasskey(createClient(config), authenticator, {
            collection: user.collection,
          })
          const status = result.verify?.status
          return { ok: status === 200, status }
        },
      }
    }
    case 'rest-login':
      return {
        run: async () => {
          const res = await createClient(config).post(`/api/${user.collection}/login`, {
            email: user.email,
            password: PASSWORD,
          })
          return { ok: res.status === 200, status: res.status }
        },
      }
    case 'sso':
      return {
        run: async () => {
          try {
            await signInVerifiedUser({ collection: user.collection, payload, userId: user.id })
            return { ok: true }
          } catch (error) {
            return { error, ok: false }
          }
        },
      }
  }
}

export const sessionCount = async (payload: Payload, user: TestUser) =>
  ((await rawUser(payload, user.collection, user.id)).sessions ?? []).length

export const SIGN_IN_WAYS: SignInWay[] = ['rest-login', 'sso', 'passkey']
