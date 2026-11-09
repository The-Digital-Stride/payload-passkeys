import type { Payload, PayloadRequest, Where } from 'payload'

import { createLocalReq } from 'payload'

import { ownPasskeysWhere } from '../collections/passkeys.js'
import { getPasskeysOptions } from './context.js'
import { confirmSignedOut, revokeAndMarkSessions, runSessionWrite } from './sessions.js'

/**
 * Removes a user's passkeys and pending registrations, and always ends every session of theirs, so
 * a planted passkey's sessions go too (M6). The password and forgot-password are untouched. The
 * engine behind `payload passkeys:reset`, and for a host's own offboarding, for example from an
 * afterChange hook when someone is disabled.
 *
 * Pass the hook's `req` so the removal joins its transaction: it commits with the save, or rolls
 * back with it. The trade-off: inside the caller's transaction a write conflict is not retried
 * (only the caller can retry a transaction), so a save that races the user's own token refresh
 * fails with the conflict and has to be made again. Without `req` it runs in its own transaction
 * and retries a conflicting write, as the CLI does.
 *
 * Throws when `collection` isn't one of the plugin's collections, or no single user matches.
 */
export const resetPasskeys = async ({
  collection,
  email,
  id,
  payload,
  req: callerReq,
}: {
  collection: string
  email?: string
  id?: number | string
  payload: Payload
  /** The caller's request, to join its transaction (see above). */
  req?: PayloadRequest
}): Promise<{ removedPasskeys: number; removedSessions: number; userId: number | string }> => {
  const options = getPasskeysOptions(payload)
  if (!options.collections.includes(collection)) {
    throw new Error(
      `"${collection}" is not a passkeys collection. Use one of: ${options.collections.join(', ')}.`,
    )
  }
  const hasId = id !== undefined && id !== ''
  if (!email && !hasId) throw new Error('Give --email or --id.')
  const req = callerReq ?? (await createLocalReq({}, payload))
  const where: Where = hasId
    ? { id: { equals: id } }
    : { email: { equals: email!.trim().toLowerCase() } }
  const { docs } = await payload.find({
    collection: collection as never,
    depth: 0,
    limit: 2,
    overrideAccess: true,
    req,
    where,
  })
  if (docs.length !== 1)
    throw new Error(
      `No user in the ${collection} collection matches ${hasId ? `id ${id}` : email}.`,
    )
  const userId = (docs[0] as { id: number | string }).id

  const passkeyWhere = ownPasskeysWhere(options, collection, userId)
  const removedPasskeys = (
    await payload.db.count({ collection: options.slugs.passkeys, req, where: passkeyWhere })
  ).totalDocs
  const sessionArgs = { collectionSlug: collection, label: 'reset', options, req, userId }
  // One transaction where it helps, so a failure leaves nothing half-done, retried when a parallel
  // refresh conflicts (not inside the caller's transaction); then re-read until no session is left
  // (src/server/sessions.ts).
  let removedSessions = await runSessionWrite({
    label: 'reset',
    req,
    work: async () => {
      await payload.db.deleteMany({ collection: options.slugs.passkeys, req, where: passkeyWhere })
      await payload.db.deleteMany({
        collection: options.slugs.challenges,
        req,
        where: {
          and: [{ authCollection: { equals: collection } }, { userId: { equals: String(userId) } }],
        },
      })
      return revokeAndMarkSessions(sessionArgs)
    },
  })
  removedSessions += await confirmSignedOut(sessionArgs)
  payload.logger.info({
    collection,
    event: 'passkeys.reset',
    msg: 'passkeys.reset',
    removedPasskeys,
    removedSessions,
    userId,
  })
  return { removedPasskeys, removedSessions, userId }
}
