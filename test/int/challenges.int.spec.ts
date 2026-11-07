import type { Payload, PayloadRequest } from 'payload'

import { createHash } from 'crypto'
import { createPayloadRequest, getPayload } from 'payload'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import type { ResolvedOptions } from '../../src/server/options.js'

import {
  ChallengeCapReached,
  ChallengeRejected,
  consumeChallenge,
  issueChallenge,
} from '../../src/server/challenges.js'
import { getPasskeysOptions } from '../../src/server/context.js'
import config from '../configs/single.js'
import { SERVER_URL } from '../helpers/api.js'

let payload: Payload
let options: ResolvedOptions

beforeAll(async () => {
  payload = await getPayload({ config })
  options = {
    ...getPasskeysOptions(payload),
    limits: { anonymousChallenges: 5, passkeysPerUser: 3 },
  }
})
afterAll(async () => {
  await payload.destroy()
})
beforeEach(async () => {
  await payload.db.deleteMany({ collection: 'passkey-challenges', where: {} })
  await payload.db.deleteMany({ collection: 'passkey-challenge-uses', where: {} })
})

const reqWith = (cookie?: string): Promise<PayloadRequest> =>
  createPayloadRequest({
    config,
    request: new Request(`${SERVER_URL}/api/users/passkeys/x`, {
      headers: cookie ? { Cookie: cookie.split(';')[0]! } : {},
      method: 'POST',
    }),
  })

const challenge = () =>
  crypto
    .getRandomValues(new Uint8Array(32))
    .reduce((s, b) => s + b.toString(16).padStart(2, '0'), '')
    .slice(0, 43)

const issue = async (
  type: 'authentication' | 'registration',
  extra: { cookie?: string; userId?: number | string } = {},
) => {
  const value = challenge()
  const { setCookie } = await issueChallenge({
    challenge: value,
    collection: 'users',
    options,
    req: await reqWith(extra.cookie),
    type,
    userHandle: type === 'registration' ? 'handle' : undefined,
    userId: extra.userId,
  })
  return { cookie: setCookie, value }
}

const consume = async (
  value: string,
  cookie: string | undefined,
  type: 'authentication' | 'registration',
  userId?: number | string,
) =>
  consumeChallenge({
    challenge: value,
    collection: 'users',
    options,
    req: await reqWith(cookie),
    type,
    userId,
  })

const reason = (p: Promise<unknown>) =>
  p.then(
    () => 'consumed',
    (e: unknown) => (e instanceof ChallengeRejected ? e.reason : String(e)),
  )

describe('issueChallenge', () => {
  it('stores only the hash of the browser key', async () => {
    const { cookie, value } = await issue('authentication')
    const key = cookie.split(';')[0]!.split('=')[1]!
    const row = (
      await payload.find({
        collection: 'passkey-challenges',
        where: { challenge: { equals: value } },
      })
    ).docs[0]!
    expect(row.browserKeyHash).toBe(createHash('sha256').update(key).digest('hex'))
    expect(JSON.stringify(row)).not.toContain(key)
  })

  it('keeps one outstanding sign-in challenge per browser (review M2)', async () => {
    const first = await issue('authentication')
    await issue('authentication', { cookie: first.cookie })
    expect((await payload.count({ collection: 'passkey-challenges' })).totalDocs).toBe(1)
    expect(await reason(consume(first.value, first.cookie, 'authentication'))).toBe(
      'unknown_challenge',
    )
  })

  it('caps outstanding sign-in challenges site-wide (review M2)', async () => {
    for (let i = 0; i < 5; i++) await issue('authentication')
    await expect(issue('authentication')).rejects.toBeInstanceOf(ChallengeCapReached)
  })

  it('keeps one registration challenge per user', async () => {
    await issue('registration', { userId: 1 })
    await issue('registration', { userId: 1 })
    expect(
      (
        await payload.count({
          collection: 'passkey-challenges',
          where: { type: { equals: 'registration' } },
        })
      ).totalDocs,
    ).toBe(1)
  })

  it('prunes expired challenges and uses', async () => {
    const past = new Date(Date.now() - 1000).toISOString()
    await payload.create({
      collection: 'passkey-challenges',
      data: {
        browserKeyHash: 'x',
        challenge: 'old',
        authCollection: 'users',
        expiresAt: past,
        type: 'authentication',
      },
    })
    await payload.create({
      collection: 'passkey-challenge-uses',
      data: { challenge: 'old-use', expiresAt: past },
    })
    await issue('authentication')
    expect(
      (
        await payload.count({
          collection: 'passkey-challenges',
          where: { challenge: { equals: 'old' } },
        })
      ).totalDocs,
    ).toBe(0)
    expect((await payload.count({ collection: 'passkey-challenge-uses' })).totalDocs).toBe(0)
  })
})

describe('consumeChallenge', () => {
  it('consumes once and deletes the row', async () => {
    const { cookie, value } = await issue('authentication')
    expect((await consume(value, cookie, 'authentication')).challenge).toBe(value)
    expect((await payload.count({ collection: 'passkey-challenges' })).totalDocs).toBe(0)
    expect(await reason(consume(value, cookie, 'authentication'))).toBe('unknown_challenge')
  })

  it('refuses a replay even while the row still exists (unique insert, review M3)', async () => {
    const { cookie, value } = await issue('authentication')
    await payload.create({
      collection: 'passkey-challenge-uses',
      data: { challenge: value, expiresAt: new Date(Date.now() + 60_000).toISOString() },
    })
    expect(await reason(consume(value, cookie, 'authentication'))).toBe('replayed')
  })

  it.each([
    ['wrong_type', 'authentication', 'registration'],
    ['wrong_type', 'registration', 'authentication'],
  ] as const)('refuses %s (%s consumed as %s)', async (expected, issuedAs, consumedAs) => {
    const { cookie, value } = await issue(issuedAs, { userId: 1 })
    expect(await reason(consume(value, cookie, consumedAs, 1))).toBe(expected)
  })

  it('refuses another browser and no browser (login CSRF)', async () => {
    const a = await issue('authentication')
    const b = await issue('authentication')
    expect(await reason(consume(a.value, b.cookie, 'authentication'))).toBe('wrong_browser')
    const c = await issue('authentication')
    expect(await reason(consume(c.value, undefined, 'authentication'))).toBe('wrong_browser')
  })

  it('refuses another user for registration', async () => {
    const { cookie, value } = await issue('registration', { userId: 1 })
    expect(await reason(consume(value, cookie, 'registration', 2))).toBe('wrong_user')
  })

  it('refuses an expired challenge and still deletes it', async () => {
    const { cookie, value } = await issue('authentication')
    await payload.db.updateOne({
      collection: 'passkey-challenges',
      data: { expiresAt: new Date(Date.now() - 1).toISOString() },
      returning: false,
      where: { challenge: { equals: value } },
    })
    expect(await reason(consume(value, cookie, 'authentication'))).toBe('expired')
    expect((await payload.count({ collection: 'passkey-challenges' })).totalDocs).toBe(0)
  })
})
