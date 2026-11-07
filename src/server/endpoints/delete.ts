import type { ResolvedOptions } from '../options.js'

import { ownPasskeysWhere } from '../../collections/passkeys.js'
import { ENDPOINTS } from '../../shared/constants.js'
import { EndpointError, json, passkeyEndpoint } from '../http.js'
import { logEvent } from '../logging.js'
import { findOwnPasskey, listPasskeysOfUser } from '../passkeyRecords.js'
import {
  confirmSignedOut,
  revokeAndMarkSessions,
  runSessionWrite,
  SessionWriteFailed,
} from '../sessions.js'

/**
 * The only way to remove a passkey (REST delete is off). With signOutOtherSessions, every session
 * but this one ends, so removing a planted passkey also ends what it signed in (review M6).
 *
 * The revoke and the delete share one transaction, retried on a write conflict with a parallel
 * refresh; the revoke goes first, so without transactions a failed revoke still leaves the passkey.
 * Revoked sessions are marked so a racing refresh can't bring them back, and the user is re-read
 * until only this session is left (src/server/sessions.ts). When the write fails, nothing was
 * removed and it answers 503 `retry`. When only that last check fails, the passkey is already
 * gone, so it answers 503 `sign_out_unconfirmed` instead: retrying the removal would find nothing
 * (404), and the client refreshes the list and says the passkey went but other sessions may not
 * have. Every session the plugin revoked is still marked, so none of them can authenticate.
 */
export const deleteEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'delete',
    auth: 'signed-in',
    collectionSlug,
    handler: async ({ body, req, user }) => {
      const row = await findOwnPasskey(req, options, collectionSlug, user.id, body.id)
      if (!row) throw new EndpointError(404, 'not_found')
      const signOut = body.signOutOtherSessions === true
      const sessionArgs = { collectionSlug, keep: user._sid, options, req, userId: user.id }
      const log = (reason?: string) =>
        logEvent(req, options, 'passkeys.removed', {
          collection: collectionSlug,
          credentialId: row.credentialId,
          reason,
          userId: user.id,
        })

      let signedOutSessions: number
      try {
        signedOutSessions = await runSessionWrite({
          label: 'delete',
          req,
          work: async () => {
            const revoked = signOut ? await revokeAndMarkSessions(sessionArgs) : 0
            await req.payload.db.deleteMany({
              collection: options.slugs.passkeys,
              req,
              where: {
                and: [
                  { id: { equals: row.id } },
                  ownPasskeysWhere(options, collectionSlug, user.id),
                ],
              },
            })
            return revoked
          },
        })
      } catch (error) {
        if (!(error instanceof SessionWriteFailed)) throw error
        req.payload.logger.error({ err: error, msg: 'passkeys: could not remove a passkey' })
        throw new EndpointError(503, 'retry')
      }
      if (signOut) {
        try {
          signedOutSessions += await confirmSignedOut({ ...sessionArgs, label: 'delete' })
        } catch (error) {
          // The passkey is gone, but a session outlived the sign-out: say exactly that.
          log('sign_out_unconfirmed')
          req.payload.logger.error({
            err: error,
            msg: 'passkeys: could not end the other sessions',
          })
          throw new EndpointError(503, 'sign_out_unconfirmed')
        }
      }
      const remaining = (await listPasskeysOfUser(req, options, collectionSlug, user.id)).length
      log(signedOutSessions ? `signed_out_${signedOutSessions}` : undefined)
      return json(req, 200, { remaining, removed: true, signedOutSessions })
    },
    options,
    path: ENDPOINTS.delete,
  })
