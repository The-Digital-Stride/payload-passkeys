import type { ResolvedOptions } from '../options.js'

import { ENDPOINTS, USER_HANDLE_FIELD } from '../../shared/constants.js'
import { json, passkeyEndpoint } from '../http.js'
import { loadRawUser } from '../mintSession.js'
import { listPasskeysOfUser, toPublicPasskey } from '../passkeyRecords.js'

/**
 * Whether passkeys work at the caller's origin. Anonymous callers learn only that (M9). The
 * signed-in owner also gets the reason, the RP ID, their passkeys (the manager's one read) and
 * `signalUserId`, the WebAuthn user.id that PublicKeyCredential.signalAllAcceptedCredentials needs.
 */
export const statusEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'status',
    auth: 'optional',
    checkOrigin: false,
    collectionSlug,
    handler: async ({ req, user }) => {
      const origin = req.headers.get('Origin')
      const available = origin !== null && options.origins.includes(origin)
      if (!user) return json(req, 200, { available })
      const [rows, raw] = await Promise.all([
        listPasskeysOfUser(req, options, collectionSlug, user.id),
        loadRawUser(req, collectionSlug, user.id),
      ])
      const handle = raw?.[USER_HANDLE_FIELD]
      return json(req, 200, {
        available,
        ...(available ? {} : { reason: origin === null ? 'no_origin' : 'origin_not_allowed' }),
        passkeys: rows.map(toPublicPasskey),
        rpID: options.rpID,
        signalUserId: typeof handle === 'string' ? handle : null,
      })
    },
    options,
    path: ENDPOINTS.status,
  })
