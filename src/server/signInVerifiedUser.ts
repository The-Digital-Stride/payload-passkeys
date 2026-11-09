import { createLocalReq } from 'payload'

import type { SignInVerifiedUserArgs, SignInVerifiedUserResult } from '../types.js'

import { getPasskeysOptions } from './context.js'
import { logEvent } from './logging.js'
import { mintSession } from './mintSession.js'

/**
 * Signs in a user the caller has already verified, such as in an SSO (OAuth or OpenID Connect)
 * callback that has checked `state` and the provider's response. It creates an ordinary Payload
 * session exactly as a passkey sign-in does: the session is added, failed-login attempts and any
 * lock are cleared, the collection's beforeLogin hooks run (and can refuse), then the plugin's
 * onSignIn (with `method: 'sso'`), then the token is signed and afterLogin runs.
 *
 * It never checks who the user is: calling it signs that user in. Server-only.
 *
 * The cookie follows the collection's `auth.cookies` settings; set `secure: true` in production.
 * Throws when `collection` isn't one of the plugin's collections, when the user doesn't exist
 * (or is unverified, where the collection verifies email), and whatever a hook throws.
 */
export const signInVerifiedUser = async ({
  collection,
  headers,
  payload,
  userId,
}: SignInVerifiedUserArgs): Promise<SignInVerifiedUserResult> => {
  const options = getPasskeysOptions(payload)
  if (!options.collections.includes(collection)) {
    throw new Error(
      `[payload-passkeys] "${collection}" is not a passkeys collection. Use one of: ${options.collections.join(', ')}.`,
    )
  }
  const req = await createLocalReq({ req: headers ? { headers } : {} }, payload)
  const minted = await mintSession({
    collectionSlug: collection,
    method: 'sso',
    onSignIn: options.onSignIn,
    req,
    userId,
  })

  const fields = { collection, method: 'sso' as const, userId }
  if (minted.wasLocked) logEvent(req, options, 'passkeys.signed_in_while_locked', fields)
  logEvent(req, options, 'passkeys.signed_in', fields)
  return { exp: minted.body.exp, setCookie: minted.setCookie, user: minted.body.user }
}
