import type { CollectionBeforeLoginHook, Where } from 'payload'

import { UnauthorizedError } from 'payload'

import type { RefuseSignInUnlessOptions, SignInAllowed } from '../types.js'

import { withoutSecrets } from './mintSession.js'

const DEFAULT_RECHECK_TIMEOUT_MS = 5_000
const TIMED_OUT = Symbol('timed out')

/**
 * What the predicate sees: the record without secrets, with the collection's slug, and without
 * the `_strategy` and `_sid` Payload adds to the sign-in's copy, so both calls get the same shape.
 */
const forPredicate = (record: Record<string, unknown>, slug: string): Record<string, unknown> => {
  const { _sid: _ignoredSid, _strategy: _ignoredStrategy, ...rest } = withoutSecrets(record)
  return { ...rest, collection: slug }
}

/**
 * A beforeLogin hook that refuses the sign-in unless `isAllowed` returns true for the user, for
 * example to keep out someone who has left. Add it to the auth collection's `hooks.beforeLogin`.
 * It runs for Payload's own login and password reset, passkey sign-in and signInVerifiedUser.
 *
 * It asks twice: once about the user the sign-in read, then about the user's record as committed
 * in the database, read again outside the sign-in's transaction. Anything but `true` refuses with
 * Payload's UnauthorizedError (401), and so does a user who has since been deleted or trashed. A
 * throw from `isAllowed` or from the re-read propagates, so the sign-in is refused either way.
 * `isAllowed` never receives `hash`, `salt`, `sessions` or the other secret fields; it gets the
 * raw stored record (depth 0, no afterRead hooks, no virtual fields) with `collection` added.
 *
 * Transactions decide what it can catch. Payload's login (and the plugin's sign-ins) read the
 * user, then write the whole record back with the new session before beforeLogin runs.
 * - With transactions (Postgres; MongoDB on a replica set; SQLite only with `transactionOptions`),
 *   that write is not yet committed, so a disable saved before it is what the re-read sees: the
 *   sign-in is refused and rolled back, and the disable stays. A disable saved after the session
 *   write lets this sign-in through (Postgres: the save waits and is kept; MongoDB: the save fails
 *   with a write conflict and must be made again).
 * - Without them (SQLite by default; MongoDB without a replica set), that write has already
 *   committed, stale value included. Only a user disabled before the sign-in began is refused; a
 *   disable saved during it is overwritten and the user stays signed in. Failed-login attempts and
 *   any lock are also cleared before this hook runs. Use transactions in production, and after
 *   disabling someone, reload their record and check the change held.
 *
 * On Postgres the re-read needs a pool connection of its own while the sign-in's transaction
 * holds one and the adapter keeps another, so the pool must allow at least 3. With read replicas
 * the re-read goes to the primary because the session write was recent; keep `isAllowed` fast. If
 * the re-read takes longer than `recheckTimeoutMs` (default 5000), the sign-in is refused and an
 * error is logged.
 */
export const refuseSignInUnless =
  (
    isAllowed: SignInAllowed,
    { recheckTimeoutMs = DEFAULT_RECHECK_TIMEOUT_MS }: RefuseSignInUnlessOptions = {},
  ): CollectionBeforeLoginHook =>
  async ({ collection, req, user }) => {
    const slug = collection?.slug
    const id = (user as null | { id?: unknown })?.id
    if (typeof slug !== 'string' || (typeof id !== 'string' && typeof id !== 'number')) {
      throw new UnauthorizedError(req.t)
    }
    if ((await isAllowed(forPredicate(user as Record<string, unknown>, slug))) !== true) {
      throw new UnauthorizedError(req.t)
    }

    const byId: Where = { id: { equals: id } }
    const where: Where = collection.trash ? { and: [byId, { deletedAt: { exists: false } }] } : byId
    let timer: ReturnType<typeof setTimeout> | undefined
    const stored = await Promise.race([
      // No req: outside the sign-in's transaction, so it sees what has been committed.
      req.payload.db.findOne<{ id: number | string } & Record<string, unknown>>({
        collection: slug,
        where,
      }),
      new Promise<typeof TIMED_OUT>((resolve) => {
        timer = setTimeout(() => resolve(TIMED_OUT), recheckTimeoutMs)
      }),
    ]).finally(() => clearTimeout(timer))

    if (stored === TIMED_OUT) {
      req.payload.logger.error({
        collection: slug,
        msg: `passkeys: refuseSignInUnless could not re-read the user within ${recheckTimeoutMs} ms, so the sign-in was refused. On Postgres, allow the pool at least 3 connections.`,
        userId: id,
      })
      throw new UnauthorizedError(req.t)
    }
    if (!stored || (await isAllowed(forPredicate(stored, slug))) !== true) {
      throw new UnauthorizedError(req.t)
    }
    return user
  }
