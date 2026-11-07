/**
 * Ending sessions reliably. Payload's refresh reads the user, then rewrites the whole `sessions`
 * list inside a transaction. A revoke that races it can fail (Postgres: a deadlock, or a unique
 * violation on `users_sessions.id`) or be undone: the refresh read the list before the revoke
 * committed and writes it back after (Postgres runs READ COMMITTED, so nothing stops it).
 *
 * So a revoke here:
 * 1. writes a marker per revoked session (a `session:` row in passkey-challenge-uses, so no schema
 *    change), in the same transaction as the revoke where there is one;
 * 2. is retried whole on a write conflict, with backoff and jitter (runSessionWrite);
 * 3. is confirmed by re-reading the user until only the kept session is left.
 * And an afterRefresh hook on each auth collection refuses to refresh a marked session. It runs
 * inside the refresh's transaction, after its write, so throwing rolls the write back; where there
 * is no transaction it removes the session again first.
 *
 * Refresh is not the only write that can undo a revoke. Payload's update fills fields the request
 * left out from the stored document, `sessions` included, and logout rewrites the whole list; one
 * that read the user before the revoke and writes after it restores every revoked session, and no
 * retry or confirmation can rule that out. So the marker is also checked where it can't be raced:
 * hideRevokedSessions drops marked sessions from every findByID and find of the user, and Payload's
 * local-jwt strategy loads the user with findByID and accepts the token only if its `sid` is in
 * `user.sessions`. A marked session therefore never authenticates, whatever is stored.
 * dropRevokedSessions keeps marked sessions out of every update through Payload, so a revived one
 * is also removed from the database by the user's next update.
 *
 * Uses only documented Payload exports; the session write itself is revokeSessions in
 * mintSession.ts.
 */
import type {
  CollectionAfterOperationHook,
  CollectionAfterRefreshHook,
  CollectionBeforeChangeHook,
  PayloadRequest,
} from 'payload'

import { commitTransaction, Forbidden, initTransaction, killTransaction } from 'payload'

import type { ResolvedOptions } from './options.js'

import { authCollectionConfig, loadRawUser, revokeSessions } from './mintSession.js'

/** Tries per write, counting the first. */
export const MAX_WRITE_ATTEMPTS = 6
/** Re-reads after the write; between them, a revoke of whatever came back. */
export const CONFIRM_ROUNDS = 4
/** Long enough for a refresh that was blocked on the revoke's locks to finish. */
const SETTLE_MS = 40
/**
 * How long a marker outlives the token lifetime. A refresh that authenticated before the markers
 * committed can still sign a token, a little later than the revoke started; the marker must outlast
 * that token too.
 */
export const MARKER_MARGIN_MS = 10 * 60 * 1000

/** The sessions could not be ended, or not confirmed ended. Safe to try again. */
export class SessionWriteFailed extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'SessionWriteFailed'
  }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
const backoff = (attempt: number) => 10 * 2 ** attempt + Math.floor(Math.random() * 25)

/** The marker's `challenge` value. Challenges are base64url, so never contain a colon. */
export const revokedSessionMarker = (collectionSlug: string, sid: string): string =>
  `session:${collectionSlug}:${sid}`

/**
 * The ids among `sids` that have a revocation marker: one query on the unique `challenge` index.
 * Throws when the lookup fails, so callers fail closed.
 */
export const findRevokedSids = async ({
  collectionSlug,
  options,
  req,
  sids,
}: {
  collectionSlug: string
  options: Pick<ResolvedOptions, 'slugs'>
  req: PayloadRequest
  sids: string[]
}): Promise<Set<string>> => {
  const revoked = new Set<string>()
  if (sids.length === 0) return revoked
  const bySid = new Map(sids.map((sid) => [revokedSessionMarker(collectionSlug, sid), sid]))
  const { docs } = await req.payload.db.find({
    collection: options.slugs.challengeUses,
    limit: 0,
    pagination: false,
    req,
    where: { challenge: { in: [...bySid.keys()] } },
  })
  for (const doc of docs as { challenge?: unknown }[]) {
    const sid = bySid.get(doc.challenge as string)
    if (sid) revoked.add(sid)
  }
  return revoked
}

type SessionRow = { id?: unknown }
type WithSessions = null | undefined | { id?: unknown; sessions?: unknown }

const sessionIdsOf = (doc: WithSessions): string[] =>
  doc && Array.isArray(doc.sessions)
    ? (doc.sessions as SessionRow[])
        .map((session) => session?.id)
        .filter((id): id is string => typeof id === 'string')
    : []

/**
 * afterOperation on each auth collection: drops marked sessions from the user documents a findByID
 * or find returns. Payload's local-jwt strategy (payload/dist/auth/strategies/jwt.js) loads the
 * user with findByID and refuses a token whose `sid` isn't in `user.sessions`, so this is what
 * stops a revoked session that a racing write put back from authenticating anything: REST,
 * GraphQL, the admin and the plugin's own endpoints alike. One query per read, none when the
 * documents carry no sessions. A failed lookup throws, and the strategy treats a throw as signed
 * out (fail closed).
 */
export const hideRevokedSessions =
  (options: ResolvedOptions): CollectionAfterOperationHook =>
  async ({ collection, operation, req, result }) => {
    let docs: WithSessions[]
    if (operation === 'findByID') docs = [result as WithSessions]
    else if (operation === 'find') docs = (result as { docs?: WithSessions[] }).docs ?? []
    else return result
    const sids = docs.flatMap(sessionIdsOf)
    if (sids.length === 0) return result
    const revoked = await findRevokedSids({ collectionSlug: collection.slug, options, req, sids })
    if (revoked.size === 0) return result
    for (const doc of docs) {
      if (!doc || !Array.isArray(doc.sessions)) continue
      const sessions = doc.sessions as SessionRow[]
      const kept = sessions.filter((session) => !revoked.has(session?.id as string))
      doc.sessions = kept
      if (kept.length !== sessions.length) {
        req.payload.logger.warn({
          collection: collection.slug,
          msg: 'passkeys: ignored a revoked session that was written back',
          userId: doc.id,
        })
      }
    }
    return result
  }

/**
 * beforeChange on each auth collection: keeps marked sessions out of an update through Payload,
 * which would otherwise write back whatever `sessions` it read. Not a defence on its own (a write
 * that read before the revoke can pass this check before the markers exist); hideRevokedSessions
 * is. Login, refresh and logout write with payload.db.updateOne and don't run it.
 */
export const dropRevokedSessions =
  (options: ResolvedOptions): CollectionBeforeChangeHook =>
  async ({ collection, data, operation, req }) => {
    if (operation !== 'update' || !Array.isArray(data?.sessions)) return data
    const sids = sessionIdsOf(data)
    if (sids.length === 0) return data
    const revoked = await findRevokedSids({ collectionSlug: collection.slug, options, req, sids })
    if (revoked.size === 0) return data
    data.sessions = (data.sessions as SessionRow[]).filter(
      (session) => !revoked.has(session?.id as string),
    )
    return data
  }

type ErrorLike = {
  cause?: unknown
  code?: unknown
  codeName?: unknown
  data?: { errors?: { path?: unknown }[] }
  hasErrorLabel?: (label: string) => boolean
  message?: unknown
  name?: unknown
}

const chain = (error: unknown): ErrorLike[] => {
  const found: ErrorLike[] = []
  let current = error
  while (current && typeof current === 'object' && found.length < 6) {
    found.push(current as ErrorLike)
    current = (current as ErrorLike).cause
  }
  return found
}

/**
 * A write lost to a concurrent one, worth retrying: a Postgres deadlock, serialization failure or
 * unique violation (Drizzle reports the last as a ValidationError on the column), SQLite busy or
 * unique, or a MongoDB write conflict.
 */
export const isWriteConflict = (error: unknown): boolean =>
  chain(error).some((e) => {
    if (['23505', '40001', '40P01'].includes(e.code as string)) return true
    if (['SQLITE_BUSY', 'SQLITE_CONSTRAINT_UNIQUE', 'SQLITE_LOCKED'].includes(e.code as string))
      return true
    if (e.code === 112 || e.codeName === 'WriteConflict') return true
    if (typeof e.hasErrorLabel === 'function' && e.hasErrorLabel('TransientTransactionError'))
      return true
    if (
      e.name === 'ValidationError' &&
      e.data?.errors?.some((field) => field.path === 'id' || field.path === 'challenge')
    )
      return true
    return (
      typeof e.message === 'string' &&
      /deadlock detected|could not serialize access|write ?conflict/i.test(e.message)
    )
  })

/**
 * Runs `work` in its own transaction where that helps, retrying it whole (a failed Postgres
 * transaction can't continue) on a write conflict. Inside a caller's transaction it runs once:
 * only the caller can retry that.
 *
 * Not on MongoDB: a transaction there fails at once on a document another transaction has written
 * and not yet committed, so a steady stream of refreshes would starve it. A write outside a
 * transaction waits for theirs instead, and a refresh that read before it then aborts with a write
 * conflict. On Drizzle the transaction is what keeps the sessions rewrite (a delete and inserts)
 * whole.
 */
export const runSessionWrite = async <T>({
  label,
  req,
  work,
}: {
  label: string
  req: PayloadRequest
  work: () => Promise<T>
}): Promise<T> => {
  for (let attempt = 1; ; attempt++) {
    const shouldCommit = req.payload.db.name !== 'mongoose' && (await initTransaction(req))
    // Without transactions (SQLite by default) Payload leaves a promise of null here.
    const callerTransaction = !shouldCommit && Boolean(await req.transactionID)
    try {
      const result = await work()
      if (shouldCommit) await commitTransaction(req)
      return result
    } catch (error) {
      if (shouldCommit) await killTransaction(req)
      if (callerTransaction || !isWriteConflict(error)) throw error
      if (attempt >= MAX_WRITE_ATTEMPTS) {
        throw new SessionWriteFailed(`passkeys: ${label} kept conflicting`, { cause: error })
      }
      req.payload.logger.warn({
        attempt,
        err: error,
        label,
        msg: 'passkeys: retrying a session write',
      })
      await sleep(backoff(attempt))
    }
  }
}

/**
 * Marks every session but `keep` as revoked and removes them. Call it inside runSessionWrite, so
 * that in a transaction the markers and the removal commit together. Returns how many it removed.
 */
export const revokeAndMarkSessions = async ({
  collectionSlug,
  keep,
  options,
  req,
  userId,
}: {
  collectionSlug: string
  keep?: string
  options: ResolvedOptions
  req: PayloadRequest
  userId: number | string
}): Promise<number> => {
  const user = await loadRawUser(req, collectionSlug, userId)
  const sids = (user?.sessions ?? []).map((session) => session.id).filter((id) => id !== keep)
  if (sids.length === 0) return 0
  // A token of a revoked session expires at most one token lifetime after the revoke (plus the
  // time a refresh already under way takes); after that the marker has nothing left to refuse.
  const lifetimeMs = authCollectionConfig(req, collectionSlug).auth.tokenExpiration * 1000
  const expiresAt = new Date(Date.now() + lifetimeMs + MARKER_MARGIN_MS).toISOString()
  const mark = async () => {
    for (const sid of sids) {
      const challenge = revokedSessionMarker(collectionSlug, sid)
      const where = { challenge: { equals: challenge } }
      if (await req.payload.db.findOne({ collection: options.slugs.challengeUses, req, where }))
        continue
      await req.payload.create({
        collection: options.slugs.challengeUses as never,
        data: { challenge, expiresAt } as never,
        overrideAccess: true,
        req,
      })
    }
  }
  // In a transaction both commit together, so write the user first: on MongoDB the window in which
  // a parallel refresh makes the write conflict starts at the transaction's first read. Without
  // one, the markers must exist before the sessions go, for refuseRevokedRefresh to see them.
  if (await req.transactionID) {
    const removed = await revokeSessions({ collectionSlug, keep, req, userId })
    await mark()
    return removed
  }
  await mark()
  return revokeSessions({ collectionSlug, keep, req, userId })
}

/**
 * After a committed revoke, re-reads the user until no session but `keep` is left, revoking again
 * whatever came back. Returns how many more it removed; throws SessionWriteFailed when sessions
 * are still there after CONFIRM_ROUNDS reads.
 */
export const confirmSignedOut = async (args: {
  collectionSlug: string
  keep?: string
  label: string
  options: ResolvedOptions
  req: PayloadRequest
  userId: number | string
}): Promise<number> => {
  const { collectionSlug, keep, label, req, userId } = args
  let removed = 0
  for (let round = 1; ; round++) {
    await sleep(SETTLE_MS)
    const user = await loadRawUser(req, collectionSlug, userId)
    const left = (user?.sessions ?? []).filter((session) => session.id !== keep).length
    if (left === 0) return removed
    if (round >= CONFIRM_ROUNDS) {
      throw new SessionWriteFailed(`passkeys: ${label} left ${left} session(s) after sign-out`)
    }
    req.payload.logger.warn({
      label,
      left,
      msg: 'passkeys: a revoked session came back; revoking again',
      round,
      userId,
    })
    removed += await runSessionWrite({ label, req, work: () => revokeAndMarkSessions(args) })
  }
}

/**
 * afterRefresh on each auth collection: refuses to refresh a session the plugin revoked. Inside
 * the refresh's transaction the throw rolls back its write; without one (SQLite by default,
 * standalone MongoDB) the write has landed, so the session is removed again first.
 */
export const refuseRevokedRefresh =
  (options: ResolvedOptions): CollectionAfterRefreshHook =>
  async ({ collection, req }) => {
    const user = req.user as { _sid?: unknown; id?: number | string } | null
    if (!user || typeof user._sid !== 'string' || user.id === undefined) return
    const sid = user._sid
    const marker = await req.payload.db.findOne({
      collection: options.slugs.challengeUses,
      req,
      where: { challenge: { equals: revokedSessionMarker(collection.slug, sid) } },
    })
    if (!marker) return
    if (!(await req.transactionID)) {
      await revokeSessions({ collectionSlug: collection.slug, only: [sid], req, userId: user.id })
    }
    req.payload.logger.warn({
      collection: collection.slug,
      msg: 'passkeys: refused to refresh a revoked session',
      userId: user.id,
    })
    throw new Forbidden(req.t)
  }
