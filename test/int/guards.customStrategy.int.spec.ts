import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import type { TestClient } from '../helpers/api.js'
import type { TestUser } from '../helpers/users.js'

import { ENDPOINTS } from '../../src/shared/constants.js'
import config, { TEST_USER_HEADER } from '../configs/customStrategy.js'
import { createClient, SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey } from '../helpers/ceremonies.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, PASSWORD } from '../helpers/users.js'

/**
 * Review L2: the signed-in endpoints take only Payload's own cookie session (`local-jwt`). A host
 * strategy that authenticates without an Authorization header, and even supplies a real `_sid`,
 * must still be refused, though the request carries a valid session cookie as well. The API-key
 * and header-JWT cases in guards.int.spec.ts can't pin this: the Authorization-header check
 * refuses them too.
 */

let payload: Payload
let user: TestUser
let client: TestClient
let passkeyId: number | string

beforeAll(async () => {
  payload = await getPayload({ config })
  user = await createUser(payload, 'users')
  client = await passwordClient(config, 'users', user.email)
  const { verify } = await registerPasskey(client, createSoftAuthenticator({ origin: SERVER_URL }))
  expect(verify?.status).toBe(200)
  passkeyId = verify!.json.passkey.id
})
afterAll(async () => {
  await payload.destroy()
})

const path = (endpoint: string) => `/api/users${endpoint}`
const asTestUser = () => ({ headers: { [TEST_USER_HEADER]: user.email } })

// Bodies that would succeed (or get past the session check) for the cookie session alone.
const signedIn: [string, () => Record<string, unknown>][] = [
  [ENDPOINTS.registerOptions, () => ({})],
  [ENDPOINTS.registerVerify, () => ({ response: { id: 'x', rawId: 'x', type: 'public-key' } })],
  [ENDPOINTS.reauth, () => ({ password: PASSWORD })],
  [ENDPOINTS.rename, () => ({ id: passkeyId, name: 'Renamed' })],
  [ENDPOINTS.delete, () => ({ id: passkeyId })],
]

describe('a custom auth strategy (review L2)', () => {
  it('really authenticates with Payload, so the refusals below are the plugin’s', async () => {
    const me = await createClient(config).get('/api/users/me', asTestUser())
    expect(me.json.user).toMatchObject({ _strategy: 'test', email: user.email, id: user.id })
    // With the cookie as well, the custom strategy still wins: it runs before local-jwt.
    const both = await client.get('/api/users/me', asTestUser())
    expect(both.json.user).toMatchObject({ _strategy: 'test', id: user.id })
  })

  it.each(signedIn)('%s refuses it, even beside a valid session cookie', async (endpoint, body) => {
    expect(client.cookies.get('payload-token')).toEqual(expect.any(String))
    const res = await client.post(path(endpoint), body(), asTestUser())
    expect(res.status).toBe(403)
    expect(res.json).toEqual({ error: 'unauthorised' })
  })

  it('the same cookie session alone is accepted', async () => {
    const res = await client.post(path(ENDPOINTS.rename), { id: passkeyId, name: 'Renamed' })
    expect(res.status).toBe(200)
  })
})
