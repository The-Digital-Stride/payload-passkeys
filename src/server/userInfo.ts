import type { PayloadRequest, SanitizedCollectionConfig } from 'payload'

import { randomBytes } from 'crypto'
import { getLoginOptions } from 'payload/shared'

import type { RawUser } from './mintSession.js'

import { USER_HANDLE_FIELD } from '../shared/constants.js'

const HANDLE = /^[A-Za-z0-9_-]{86}$/

/**
 * The user's WebAuthn user.id (64 random bytes), created on first use with a partial write.
 * Each passkey row keeps its own copy, so losing this to a racing whole-document write-back
 * never orphans a passkey (review L4).
 */
export const ensureUserHandle = async (
  req: PayloadRequest,
  collectionSlug: string,
  user: RawUser,
): Promise<string> => {
  const existing = user[USER_HANDLE_FIELD]
  if (typeof existing === 'string' && HANDLE.test(existing)) return existing
  const handle = randomBytes(64).toString('base64url')
  await req.payload.db.updateOne({
    collection: collectionSlug,
    data: { [USER_HANDLE_FIELD]: handle },
    id: user.id,
    req,
    returning: false,
  })
  return handle
}

/** user.name (email, or username for username logins) and user.displayName (useAsTitle). */
export const webauthnUserNames = (
  config: SanitizedCollectionConfig,
  user: RawUser,
): { displayName: string; name: string } => {
  const { canLoginWithEmail } = getLoginOptions(config.auth.loginWithUsername)
  const email = typeof user.email === 'string' ? user.email : ''
  const username = typeof user.username === 'string' ? user.username : ''
  const name = (canLoginWithEmail && email) || username || email || String(user.id)
  const titleField = config.admin.useAsTitle
  const title = titleField && titleField !== 'id' ? user[titleField] : undefined
  const displayName = typeof title === 'string' && title.trim() ? title.trim().slice(0, 64) : name
  return { displayName, name }
}

export const isFreshSession = (user: RawUser, sid: string, freshMs: number): boolean => {
  const session = user.sessions?.find((s) => s.id === sid)
  const created = session?.createdAt ? Date.parse(String(session.createdAt)) : Number.NaN
  return Number.isFinite(created) && Date.now() - created <= freshMs
}
