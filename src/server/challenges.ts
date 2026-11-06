import type { PayloadRequest, Where } from 'payload'

import { createHash, randomBytes, timingSafeEqual } from 'crypto'

import type { CeremonyType } from './cookies.js'
import type { ResolvedOptions } from './options.js'

import { CHALLENGE_TTL_MS } from '../shared/constants.js'
import {
  browserKeyCookie,
  browserKeyCookieName,
  clearBrowserKeyCookie,
  readCookie,
} from './cookies.js'

export type ChallengeRecord = {
  browserKeyHash: string
  challenge: string
  collection: string
  expiresAt: string
  id: number | string
  type: CeremonyType
  userHandle?: null | string
  userId?: null | string
}

export type ChallengeRejection =
  | 'expired'
  | 'replayed'
  | 'unknown_challenge'
  | 'wrong_browser'
  | 'wrong_collection'
  | 'wrong_type'
  | 'wrong_user'

export class ChallengeRejected extends Error {
  readonly reason: ChallengeRejection
  constructor(reason: ChallengeRejection) {
    super(`Challenge rejected: ${reason}`)
    this.name = 'ChallengeRejected'
    this.reason = reason
  }
}

export class ChallengeCapReached extends Error {
  constructor() {
    super('Too many outstanding passkey sign-in challenges')
    this.name = 'ChallengeCapReached'
  }
}

const sha256Hex = (value: string): string => createHash('sha256').update(value).digest('hex')

const sameHash = (a: string, b: string): boolean => {
  const left = Buffer.from(a, 'hex')
  const right = Buffer.from(b, 'hex')
  return left.length === 32 && right.length === 32 && timingSafeEqual(left, right)
}

const prune = async (req: PayloadRequest, options: ResolvedOptions): Promise<void> => {
  const where: Where = { expiresAt: { less_than: new Date().toISOString() } }
  await req.payload.db.deleteMany({ collection: options.slugs.challenges, req, where })
  await req.payload.db.deleteMany({ collection: options.slugs.challengeUses, req, where })
}

/**
 * Stores a challenge the server generated and returns the browser-key cookie that binds it to
 * this browser. The caller sends the cookie with the options response.
 */
export const issueChallenge = async ({
  challenge,
  collection,
  options,
  req,
  type,
  userHandle,
  userId,
}: {
  challenge: string
  collection: string
  options: ResolvedOptions
  req: PayloadRequest
  type: CeremonyType
  userHandle?: string
  userId?: number | string
}): Promise<{ cookieName: string; setCookie: string }> => {
  const { payload } = req
  await prune(req, options)

  const cookieName = browserKeyCookieName(type, collection, options.secureCookies)
  if (type === 'authentication') {
    const previous = readCookie(req, cookieName)
    if (previous) {
      await payload.db.deleteMany({
        collection: options.slugs.challenges,
        req,
        where: {
          and: [
            { type: { equals: 'authentication' } },
            { browserKeyHash: { equals: sha256Hex(previous) } },
          ],
        },
      })
    }
    const { totalDocs } = await payload.db.count({
      collection: options.slugs.challenges,
      req,
      where: { type: { equals: 'authentication' } },
    })
    if (totalDocs >= options.limits.anonymousChallenges) throw new ChallengeCapReached()
  } else {
    if (userId === undefined) throw new Error('A registration challenge needs a user')
    await payload.db.deleteMany({
      collection: options.slugs.challenges,
      req,
      where: {
        and: [
          { type: { equals: 'registration' } },
          { collection: { equals: collection } },
          { userId: { equals: String(userId) } },
        ],
      },
    })
  }

  const browserKey = randomBytes(32).toString('base64url')
  await payload.create({
    collection: options.slugs.challenges as never,
    data: {
      browserKeyHash: sha256Hex(browserKey),
      challenge,
      collection,
      expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS).toISOString(),
      type,
      ...(userHandle ? { userHandle } : {}),
      ...(userId !== undefined ? { userId: String(userId) } : {}),
    } as never,
    overrideAccess: true,
    req,
  })
  return { cookieName, setCookie: browserKeyCookie(cookieName, browserKey, options.secureCookies) }
}

/** The cookie line that clears this ceremony's browser key. Send it with every verify response. */
export const clearChallengeCookie = (
  options: ResolvedOptions,
  type: CeremonyType,
  collection: string,
): string =>
  clearBrowserKeyCookie(
    browserKeyCookieName(type, collection, options.secureCookies),
    options.secureCookies,
  )

/**
 * Single use, before any verification. The unique insert is the lock: of two parallel requests
 * with the same challenge, exactly one insert succeeds on every adapter (review M3). The row is
 * deleted whatever happens next, then checked.
 */
export const consumeChallenge = async ({
  challenge,
  collection,
  options,
  req,
  type,
  userId,
}: {
  challenge: string
  collection: string
  options: ResolvedOptions
  req: PayloadRequest
  type: CeremonyType
  userId?: number | string
}): Promise<ChallengeRecord> => {
  const { payload } = req
  const found = await payload.find({
    collection: options.slugs.challenges as never,
    depth: 0,
    limit: 1,
    overrideAccess: true,
    pagination: false,
    req,
    where: { challenge: { equals: challenge } },
  })
  const record = found.docs[0] as ChallengeRecord | undefined
  if (!record) throw new ChallengeRejected('unknown_challenge')

  try {
    await payload.create({
      collection: options.slugs.challengeUses as never,
      data: { challenge, expiresAt: record.expiresAt } as never,
      overrideAccess: true,
      req,
    })
  } catch {
    throw new ChallengeRejected('replayed')
  }
  await payload.db.deleteMany({
    collection: options.slugs.challenges,
    req,
    where: { id: { equals: record.id } },
  })

  if (record.type !== type) throw new ChallengeRejected('wrong_type')
  if (record.collection !== collection) throw new ChallengeRejected('wrong_collection')
  if (!(Date.parse(record.expiresAt) > Date.now())) throw new ChallengeRejected('expired')
  const key = readCookie(req, browserKeyCookieName(type, collection, options.secureCookies))
  if (!key || !sameHash(sha256Hex(key), record.browserKeyHash))
    throw new ChallengeRejected('wrong_browser')
  if (type === 'registration' && record.userId !== String(userId))
    throw new ChallengeRejected('wrong_user')
  return record
}
