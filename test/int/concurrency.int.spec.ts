import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import type { ApiResult } from '../helpers/api.js'

import config from '../configs/single.js'
import { cloneWithCookies, createClient, SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey } from '../helpers/ceremonies.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, rawUser } from '../helpers/users.js'

/**
 * Review M3: consuming a challenge is a unique insert, the one write that is atomic on every
 * adapter. Fire the same response several times at once and exactly one may succeed.
 */

const PARALLEL = 4
const ROUNDS = 5

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const sessionCount = async (id: number | string) =>
  ((await rawUser(payload, 'users', id)).sessions ?? []).length

/** One winner; every loser gets the ordinary generic refusal, not a server error. */
const expectOneWinner = (results: ApiResult[], error: string) => {
  expect(results.map((r) => r.status).sort()).toEqual([
    200,
    ...Array.from({ length: PARALLEL - 1 }, () => 400),
  ])
  for (const loser of results.filter((r) => r.status !== 200)) {
    expect(loser.json).toEqual({ error })
    expect(loser.headers.getSetCookie().some((line) => line.startsWith('payload-token='))).toBe(
      false,
    )
  }
}

describe('one challenge, many parallel verifies (review M3)', () => {
  it(`signs in exactly once, ${ROUNDS} rounds of ${PARALLEL}`, async () => {
    const user = await createUser(payload, 'users')
    const authenticator = createSoftAuthenticator({ origin: SERVER_URL })
    const { verify } = await registerPasskey(
      await passwordClient(config, 'users', user.email),
      authenticator,
    )
    expect(verify!.status).toBe(200)

    for (let round = 0; round < ROUNDS; round++) {
      const before = await sessionCount(user.id)
      const client = createClient(config)
      const options = (await client.post('/api/users/passkeys/sign-in/options')).json.options
      const response = await authenticator.authenticate(options)
      const results = await Promise.all(
        Array.from({ length: PARALLEL }, () =>
          cloneWithCookies(config, client.cookies).post('/api/users/passkeys/sign-in/verify', {
            response,
          }),
        ),
      )
      expectOneWinner(results, 'sign_in_failed')
      expect(await sessionCount(user.id)).toBe(before + 1)
    }
  })

  it('registers exactly once', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    const options = (await client.post('/api/users/passkeys/register/options')).json.options
    const response = await createSoftAuthenticator({ origin: SERVER_URL }).register(options)
    const results = await Promise.all(
      Array.from({ length: PARALLEL }, () =>
        cloneWithCookies(config, client.cookies).post('/api/users/passkeys/register/verify', {
          response,
        }),
      ),
    )
    expectOneWinner(results, 'registration_failed')
    expect(
      (
        await payload.count({
          collection: 'passkeys',
          overrideAccess: true,
          where: { user: { equals: user.id } },
        })
      ).totalDocs,
    ).toBe(1)
    expect(
      (
        await payload.count({
          collection: 'passkeys',
          overrideAccess: true,
          where: { credentialId: { equals: response.id } },
        })
      ).totalDocs,
    ).toBe(1)
  })
})
