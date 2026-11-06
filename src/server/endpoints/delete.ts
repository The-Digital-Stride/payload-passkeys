import type { ResolvedOptions } from '../options.js'

import { ownPasskeysWhere } from '../../collections/passkeys.js'
import { ENDPOINTS } from '../../shared/constants.js'
import { EndpointError, json, passkeyEndpoint } from '../http.js'
import { logEvent } from '../logging.js'
import { revokeSessions } from '../mintSession.js'
import { findOwnPasskey, listPasskeysOfUser } from '../passkeyRecords.js'

/**
 * The only way to remove a passkey (REST delete is off). With signOutOtherSessions, every session
 * but this one ends, so removing a planted passkey also ends what it signed in (review M6).
 */
export const deleteEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'delete',
    auth: 'signed-in',
    collectionSlug,
    handler: async ({ body, req, user }) => {
      const row = await findOwnPasskey(req, options, collectionSlug, user.id, body.id)
      if (!row) throw new EndpointError(404, 'not_found')
      await req.payload.db.deleteMany({
        collection: options.slugs.passkeys,
        req,
        where: {
          and: [{ id: { equals: row.id } }, ownPasskeysWhere(options, collectionSlug, user.id)],
        },
      })
      const signedOutSessions =
        body.signOutOtherSessions === true
          ? await revokeSessions({ collectionSlug, keep: user._sid, req, userId: user.id })
          : 0
      const remaining = (await listPasskeysOfUser(req, options, collectionSlug, user.id)).length
      logEvent(req, options, 'passkeys.removed', {
        collection: collectionSlug,
        credentialId: row.credentialId,
        reason: signedOutSessions ? `signed_out_${signedOutSessions}` : undefined,
        userId: user.id,
      })
      return json(req, 200, { remaining, removed: true, signedOutSessions })
    },
    options,
    path: ENDPOINTS.delete,
  })
