import type { ResolvedOptions } from '../options.js'

import { ENDPOINTS, USER_HANDLE_FIELD } from '../../shared/constants.js'
import { ceremoniesDisabledReason } from '../health.js'
import { json, passkeyEndpoint } from '../http.js'
import { loadRawUser } from '../mintSession.js'
import { listPasskeysOfUser, toPublicPasskey } from '../passkeyRecords.js'

/**
 * Whether passkeys work at the caller's origin. Anonymous callers learn only that (M9). The
 * signed-in owner also gets the reason, the RP ID, their passkeys (the manager's one read) and
 * `signalUserId`, the WebAuthn user.id that PublicKeyCredential.signalAllAcceptedCredentials needs.
 * While boot has turned the ceremonies off, `available` is false and the owner's reason `indexes`.
 */
export const statusEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'status',
    auth: 'optional',
    checkOrigin: false,
    collectionSlug,
    handler: async ({ req, user }) => {
      const origin = req.headers.get('Origin')
      const disabled = ceremoniesDisabledReason(req.payload)
      const available = !disabled && origin !== null && options.origins.includes(origin)
      if (!user) return json(req, 200, { available })
      const reason = disabled ?? (origin === null ? 'no_origin' : 'origin_not_allowed')
      const [rows, raw] = await Promise.all([
        listPasskeysOfUser(req, options, collectionSlug, user.id),
        loadRawUser(req, collectionSlug, user.id),
      ])
      const handle = raw?.[USER_HANDLE_FIELD]
      return json(req, 200, {
        available,
        ...(available ? {} : { reason }),
        passkeys: rows.map(toPublicPasskey),
        rpID: options.rpID,
        signalUserId: typeof handle === 'string' ? handle : null,
      })
    },
    options,
    path: ENDPOINTS.status,
  })
