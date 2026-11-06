/**
 * The Payload adapter. Every undocumented Payload auth helper the plugin uses is imported here and
 * nowhere else, and test/int/mintSession.contract.int.spec.ts pins its behaviour per Payload minor.
 *
 * Differences from loginOperation, by design:
 * - no password check (the caller verified a passkey);
 * - lockUntil does not refuse a passkey sign-in (review M5); the caller logs it;
 * - beforeOperation/afterOperation for 'login' are not run (not exported; review L8). The plugin's
 *   onSignIn option is the documented substitute.
 */
import type { CollectionSlug, PayloadRequest, SanitizedCollectionConfig, TypedUser } from 'payload'

import {
  commitTransaction,
  getFieldsToSign,
  initTransaction,
  jwtSign,
  killTransaction,
  loginOperation,
  resetLoginAttempts,
} from 'payload'
import { addSessionToUser, generatePayloadCookie, getLoginOptions } from 'payload/shared'

import type { OnSignInHook, PublicPasskey } from '../types.js'

import { USER_HANDLE_FIELD } from '../shared/constants.js'

type Session = { createdAt?: Date | null | string; expiresAt: Date | string; id: string }

export type RawUser = Record<string, unknown> & {
  email?: string
  id: number | string
  lockUntil?: Date | null | string
  sessions?: Session[]
  username?: string
}

export type SignInResponseBody = {
  exp: number
  message: string
  token?: string
  user: Record<string, unknown>
}

export type SessionResult = { body: SignInResponseBody; setCookie: string; sid: string }
export type MintResult = SessionResult & { wasLocked: boolean }

export class SignInRefused extends Error {
  readonly reason: string
  constructor(reason: string) {
    super(`Passkey sign-in refused: ${reason}`)
    this.name = 'SignInRefused'
    this.reason = reason
  }
}

/** Never sent to a browser, even where field access would let the owner read them (review M1). */
export const SECRET_USER_KEYS = [
  'hash',
  'salt',
  'sessions',
  'apiKey',
  'apiKeyIndex',
  'resetPasswordToken',
  'resetPasswordExpiration',
  '_verificationToken',
  'loginAttempts',
  'lockUntil',
  USER_HANDLE_FIELD,
] as const

export const authCollectionConfig = (
  req: PayloadRequest,
  slug: string,
): SanitizedCollectionConfig => {
  const collection = req.payload.collections[slug as CollectionSlug]
  if (!collection?.config.auth) throw new SignInRefused('not_an_auth_collection')
  return collection.config
}

export const isLocked = (lockUntil: unknown): boolean => {
  if (!lockUntil) return false
  const until = new Date(lockUntil as string).getTime()
  return Number.isFinite(until) && until > Date.now()
}

/** The raw stored user (hash, salt and sessions included). Never return it to a client. */
export const loadRawUser = async (
  req: PayloadRequest,
  slug: string,
  id: number | string,
): Promise<null | RawUser> => {
  const config = authCollectionConfig(req, slug)
  const byId = { id: { equals: id } }
  const where = config.trash ? { and: [byId, { deletedAt: { exists: false } }] } : byId
  return (await req.payload.db.findOne({ collection: slug, req, where })) as null | RawUser
}

/** The identifier Payload's login operation expects for this user. */
export const loginIdentifier = (
  config: SanitizedCollectionConfig,
  user: RawUser,
): { email: string } | { username: string } => {
  const { canLoginWithEmail } = getLoginOptions(config.auth.loginWithUsername)
  if (canLoginWithEmail && typeof user.email === 'string' && user.email)
    return { email: user.email }
  if (typeof user.username === 'string' && user.username) return { username: user.username }
  throw new SignInRefused('no_login_identifier')
}

/** The user as /me would show it to its owner, minus every secret (review M1). */
export const toResponseUser = async ({
  collectionSlug,
  req,
  sid,
  user,
}: {
  collectionSlug: string
  req: PayloadRequest
  sid: string
  user: RawUser
}): Promise<Record<string, unknown>> => {
  const config = authCollectionConfig(req, collectionSlug)
  const doc = (await req.payload.findByID({
    collection: collectionSlug as CollectionSlug,
    depth: config.auth.depth,
    id: user.id,
    overrideAccess: false,
    req,
    showHiddenFields: false,
    user: {
      ...user,
      _sid: sid,
      _strategy: 'local-jwt',
      collection: collectionSlug,
    } as unknown as TypedUser,
  })) as Record<string, unknown>
  const clean: Record<string, unknown> = { ...doc }
  for (const key of SECRET_USER_KEYS) delete clean[key]
  return { ...clean, _strategy: 'local-jwt', collection: collectionSlug }
}

/**
 * Removes sessions from a user, with the same whole-document write core's logout uses.
 * `only`: remove these sids. Otherwise keep only `keep` (or none). Returns how many were removed.
 */
export const revokeSessions = async ({
  collectionSlug,
  keep,
  only,
  req,
  userId,
}: {
  collectionSlug: string
  keep?: string
  only?: string[]
  req: PayloadRequest
  userId: number | string
}): Promise<number> => {
  const user = await loadRawUser(req, collectionSlug, userId)
  if (!user || !Array.isArray(user.sessions) || user.sessions.length === 0) return 0
  const before = user.sessions.length
  user.sessions = user.sessions.filter((session) =>
    only ? !only.includes(session.id) : session.id === keep,
  )
  if (user.sessions.length === before) return 0
  user.updatedAt = null
  await req.payload.db.updateOne({
    collection: collectionSlug,
    data: user,
    id: userId,
    req,
    returning: false,
  })
  return before - user.sessions.length
}

const sidFromToken = (token: string): string => {
  const claims = JSON.parse(
    Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8'),
  ) as {
    sid?: unknown
  }
  if (typeof claims.sid !== 'string') throw new SignInRefused('no_session_id')
  return claims.sid
}

const cookieFor = (req: PayloadRequest, config: SanitizedCollectionConfig, token: string): string =>
  generatePayloadCookie({
    collectionAuthConfig: config.auth,
    cookiePrefix: req.payload.config.cookiePrefix,
    token,
  })

/**
 * Mints an ordinary Payload session for a user who has just proved a passkey. Mirrors
 * loginOperation's order (Payload 3.90.2): transaction, addSessionToUser, getFieldsToSign,
 * resetLoginAttempts, beforeLogin, jwtSign, afterLogin, commit; on any throw, revoke and roll back.
 */
export const mintSession = async ({
  collectionSlug,
  onSignIn,
  passkey,
  req,
  userId,
}: {
  collectionSlug: string
  onSignIn?: OnSignInHook
  passkey?: PublicPasskey
  req: PayloadRequest
  userId: number | string
}): Promise<MintResult> => {
  const { payload } = req
  const config = authCollectionConfig(req, collectionSlug)
  const auth = config.auth
  if (!auth.useSessions) throw new SignInRefused('sessions_disabled')

  const user = await loadRawUser(req, collectionSlug, userId)
  if (!user) throw new SignInRefused('user_missing')
  if (auth.verify && user._verified === false) throw new SignInRefused('unverified')
  const wasLocked = isLocked(user.lockUntil)

  user.collection = collectionSlug
  user._strategy = 'local-jwt'

  const shouldCommit = await initTransaction(req)
  let sid: string | undefined
  try {
    sid = (
      await addSessionToUser({
        collectionConfig: config,
        payload,
        req,
        user: user as unknown as TypedUser,
      })
    ).sid
    if (!sid) throw new SignInRefused('sessions_disabled')
    user._sid = sid

    const fieldsToSign = getFieldsToSign({
      collectionConfig: config,
      email: typeof user.email === 'string' ? user.email : '',
      sid,
      user: user as unknown as PayloadRequest['user'],
    })

    if (auth.maxLoginAttempts > 0) {
      await resetLoginAttempts({ collection: config, doc: user, payload, req })
    }

    let hookedUser: RawUser = user
    for (const hook of config.hooks?.beforeLogin ?? []) {
      hookedUser =
        ((await hook({
          collection: config,
          context: req.context,
          req,
          user: hookedUser as never,
        })) as RawUser) || hookedUser
    }
    if (onSignIn) await onSignIn({ collection: collectionSlug, passkey, req, user: hookedUser })

    const { exp, token } = await jwtSign({
      fieldsToSign,
      secret: payload.secret,
      tokenExpiration: auth.tokenExpiration,
    })
    req.user = hookedUser as unknown as PayloadRequest['user']

    for (const hook of config.hooks?.afterLogin ?? []) {
      hookedUser =
        ((await hook({
          collection: config,
          context: req.context,
          req,
          token,
          user: hookedUser as never,
        })) as RawUser) || hookedUser
    }

    const responseUser = await toResponseUser({ collectionSlug, req, sid, user })
    if (shouldCommit) await commitTransaction(req)

    return {
      body: {
        exp,
        message: req.t('authentication:passed'),
        ...(auth.removeTokenFromResponses ? {} : { token }),
        user: responseUser,
      },
      setCookie: cookieFor(req, config, token),
      sid,
      wasLocked,
    }
  } catch (error) {
    if (sid) {
      await revokeSessions({ collectionSlug, only: [sid], req, userId: user.id }).catch(
        (revokeError: unknown) =>
          payload.logger.error({
            err: revokeError,
            msg: 'passkeys: failed to revoke a session after a refused sign-in',
          }),
      )
    }
    await killTransaction(req)
    throw error
  }
}

/**
 * Re-authentication with the password for the fresh-session rule (review H1). Runs Payload's own
 * login operation for the signed-in user (lockout, attempt counting, beforeLogin and afterLogin
 * all apply), moves the browser onto the new session and revokes the old one.
 */
export const reauthenticate = async ({
  collectionSlug,
  password,
  previousSid,
  req,
  userId,
}: {
  collectionSlug: string
  password: string
  previousSid: string
  req: PayloadRequest
  userId: number | string
}): Promise<SessionResult> => {
  const config = authCollectionConfig(req, collectionSlug)
  const user = await loadRawUser(req, collectionSlug, userId)
  if (!user) throw new SignInRefused('user_missing')

  const result = await loginOperation({
    // authCollectionConfig above has already thrown if the collection is missing.
    collection: req.payload.collections[collectionSlug as CollectionSlug]!,
    data: { ...loginIdentifier(config, user), password } as never,
    req,
  })
  if (!result.token) throw new SignInRefused('login_failed')
  const sid = sidFromToken(result.token)
  await revokeSessions({ collectionSlug, only: [previousSid], req, userId })

  const fresh = await loadRawUser(req, collectionSlug, userId)
  return {
    body: {
      exp: result.exp ?? 0,
      message: req.t('authentication:passed'),
      ...(config.auth.removeTokenFromResponses ? {} : { token: result.token }),
      user: await toResponseUser({ collectionSlug, req, sid, user: fresh ?? user }),
    },
    setCookie: cookieFor(req, config, result.token),
    sid,
  }
}
