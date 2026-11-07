import type { Payload, Where } from 'payload'

import { createLocalReq } from 'payload'

import { ownPasskeysWhere } from '../collections/passkeys.js'
import { getPasskeysOptions } from './context.js'
import { confirmSignedOut, revokeAndMarkSessions, runSessionWrite } from './sessions.js'

/**
 * For a site owner locked out of their passkeys. Removes the user's passkeys and pending
 * registrations, and always ends every session, so a planted passkey's sessions go too (M6).
 * The password and forgot-password are untouched.
 */
export const resetPasskeys = async ({
  collection,
  email,
  id,
  payload,
}: {
  collection: string
  email?: string
  id?: string
  payload: Payload
}): Promise<{ removedPasskeys: number; removedSessions: number; userId: number | string }> => {
  const options = getPasskeysOptions(payload)
  if (!options.collections.includes(collection)) {
    throw new Error(
      `"${collection}" is not a passkeys collection. Use one of: ${options.collections.join(', ')}.`,
    )
  }
  if (!email && !id) throw new Error('Give --email or --id.')
  const where: Where = id
    ? { id: { equals: id } }
    : { email: { equals: email!.trim().toLowerCase() } }
  const { docs } = await payload.find({
    collection: collection as never,
    depth: 0,
    limit: 2,
    overrideAccess: true,
    where,
  })
  if (docs.length !== 1)
    throw new Error(`No ${collection} user matches ${id ? `id ${id}` : email}.`)
  const userId = (docs[0] as { id: number | string }).id

  const req = await createLocalReq({}, payload)
  const passkeyWhere = ownPasskeysWhere(options, collection, userId)
  const removedPasskeys = (
    await payload.db.count({ collection: options.slugs.passkeys, req, where: passkeyWhere })
  ).totalDocs
  const sessionArgs = { collectionSlug: collection, label: 'reset', options, req, userId }
  // One transaction where it helps, so a failure leaves nothing half-done, retried when a parallel
  // refresh conflicts; then re-read until no session is left (src/server/sessions.ts).
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
