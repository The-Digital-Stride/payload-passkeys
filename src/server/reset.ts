import type { Payload, Where } from 'payload'

import { commitTransaction, createLocalReq, initTransaction, killTransaction } from 'payload'

import { ownPasskeysWhere } from '../collections/passkeys.js'
import { getPasskeysOptions } from './context.js'
import { revokeSessions } from './mintSession.js'

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
  // One transaction where the adapter has them, so a failure leaves nothing half-done.
  const shouldCommit = await initTransaction(req)
  let removedPasskeys: number
  let removedSessions: number
  try {
    const passkeyWhere = ownPasskeysWhere(options, collection, userId)
    const counted = await payload.db.count({
      collection: options.slugs.passkeys,
      req,
      where: passkeyWhere,
    })
    removedPasskeys = counted.totalDocs
    await payload.db.deleteMany({ collection: options.slugs.passkeys, req, where: passkeyWhere })
    await payload.db.deleteMany({
      collection: options.slugs.challenges,
      req,
      where: {
        and: [{ authCollection: { equals: collection } }, { userId: { equals: String(userId) } }],
      },
    })
    removedSessions = await revokeSessions({ collectionSlug: collection, req, userId })
    if (shouldCommit) await commitTransaction(req)
  } catch (error) {
    await killTransaction(req)
    throw error
  }
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
