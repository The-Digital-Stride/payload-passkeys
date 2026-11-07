import type { ResolvedOptions } from '../options.js'

import { ENDPOINTS } from '../../shared/constants.js'
import { EndpointError, json, passkeyEndpoint } from '../http.js'
import { logEvent } from '../logging.js'
import { reauthenticate } from '../mintSession.js'

/**
 * Re-entering the password for the fresh-session rule (review H1). A real Payload sign-in for
 * the signed-in user: the identifier comes from the session, never the body; lockout and attempt
 * counting apply; the browser moves to the new session and the old one is revoked.
 */
export const reauthEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'reauth',
    auth: 'signed-in',
    collectionSlug,
    handler: async ({ body, req, user }) => {
      const { password } = body
      if (typeof password !== 'string' || !password || password.length > 1024) {
        throw new EndpointError(400, 'bad_request')
      }
      try {
        const result = await reauthenticate({
          collectionSlug,
          password,
          previousSid: user._sid,
          req,
          userId: user.id,
        })
        logEvent(req, options, 'passkeys.reauthenticated', {
          collection: collectionSlug,
          userId: user.id,
        })
        return json(req, 200, result.body, [result.setCookie])
      } catch (error) {
        logEvent(req, options, 'passkeys.reauth_failed', {
          collection: collectionSlug,
          reason: error instanceof Error ? error.name : 'unknown',
          userId: user.id,
        })
        return json(req, 401, { error: 'reauth_failed' })
      }
    },
    options,
    path: ENDPOINTS.reauth,
  })
