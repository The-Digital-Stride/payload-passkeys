import type { Payload } from 'payload'

import type { ResolvedOptions } from './options.js'

import { setCeremoniesDisabled } from './health.js'

type IndexInfo = { key: Record<string, unknown>; name?: string; unique?: boolean }
/** The part of a Mongoose model this needs; db-mongodb keeps one per slug on payload.db.collections. */
type MongooseModel = {
  collection?: { indexes?: () => Promise<IndexInfo[]> }
  createIndexes?: () => Promise<unknown>
}

/**
 * On MongoDB, single use rests on unique indexes: passkey-challenge-uses.challenge (the replay
 * guard, review M3), passkey-challenges.challenge and passkeys.credentialId. db-mongodb builds
 * indexes only when the host sets `ensureIndexes` or leaves Mongoose's `autoIndex` on, and then in
 * the background (connect.js, Payload 3.90.2). So build them here, in onInit, before the first
 * request, and check they exist. createIndexes is idempotent for an index that already exists.
 * Returns false when any is missing.
 */
const ensureMongoIndexes = async (payload: Payload, options: ResolvedOptions): Promise<boolean> => {
  if (payload.db.name !== 'mongoose') return true
  const models = (payload.db as unknown as { collections?: Record<string, MongooseModel> })
    .collections
  const required: [slug: string, field: string][] = [
    [options.slugs.challengeUses, 'challenge'],
    [options.slugs.challenges, 'challenge'],
    [options.slugs.passkeys, 'credentialId'],
  ]
  let healthy = true
  for (const [slug, field] of required) {
    const model = models?.[slug]
    try {
      await model?.createIndexes?.()
    } catch (error) {
      payload.logger.error({ err: error, msg: `passkeys: could not build the indexes on ${slug}` })
    }
    const indexes = (await model?.collection?.indexes?.().catch(() => [])) ?? []
    if (!indexes.some((index) => index.key[field] === 1 && index.unique)) {
      healthy = false
      payload.logger.error({
        msg: `passkeys: the unique index on ${slug}.${field} is missing, so a challenge or passkey could be used twice. Check the database user can create indexes, and that no duplicate values exist.`,
      })
    }
  }
  return healthy
}

export const bootPasskeys = async (payload: Payload, options: ResolvedOptions): Promise<void> => {
  payload.logger.info({
    collections: options.collections,
    enabled: options.enabled,
    msg: 'passkeys: ready',
    origins: options.origins,
    rpID: options.rpID,
  })
  for (const warning of options.warnings) payload.logger.warn({ msg: `passkeys: ${warning}` })
  if (process.env.NODE_ENV === 'production' && options.rateLimitIsDefault) {
    payload.logger.warn({
      msg: 'passkeys: no rateLimit hook is set. Payload has no IP rate limiter of its own; pass `rateLimit` (see the README for Vercel WAF and Upstash examples).',
    })
  }
  // Fail closed for the ceremonies only: password sign-in and the rest of the admin keep working.
  const healthy = await ensureMongoIndexes(payload, options)
  setCeremoniesDisabled(payload, healthy ? null : 'indexes')
  if (!healthy) {
    payload.logger.error({
      msg: 'passkeys: passkey sign-in and registration are off until the unique indexes exist. Password sign-in still works. Fix the cause above and restart.',
    })
  }
}
