import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { passkeyEndpoints } from '../../src/server/endpoints/index.js'
import { getPasskeysOptions } from '../../src/server/context.js'
import config from '../configs/signInAgain.js'
import { ageNewestSession, passwordClient } from '../helpers/ceremonies.js'
import { createUser, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const OPTIONS = '/api/users/passkeys/register/options'

describe("reauthentication: 'sign-in-again'", () => {
  it('has no reauth endpoint, so no password can be guessed through it', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    await ageNewestSession(payload, 'users', user.id, 30)
    const res = await client.post('/api/users/passkeys/reauth', { password: 'wrong' })
    expect(res.status).toBe(404)
    expect((await rawUser(payload, 'users', user.id)).loginAttempts ?? 0).toBe(0)
  })

  it('still answers reauth_required to a stale session', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    await ageNewestSession(payload, 'users', user.id, 11)
    const res = await client.post(OPTIONS)
    expect(res.status).toBe(403)
    expect(res.json).toEqual({ error: 'reauth_required' })
  })

  it('lets a fresh session add a passkey', async () => {
    const user = await createUser(payload, 'users')
    const res = await (await passwordClient(config, 'users', user.email)).post(OPTIONS)
    expect(res.status).toBe(200)
    expect(res.json.options.challenge).toEqual(expect.any(String))
  })
})

describe('the endpoints each mode registers', () => {
  const paths = (reauthentication: 'password' | 'sign-in-again') =>
    passkeyEndpoints({ ...getPasskeysOptions(payload), reauthentication }, 'users').map(
      (endpoint) => endpoint.path,
    )

  it("registers reauth only in 'password' mode, and every other endpoint in both", () => {
    expect(paths('password')).toContain('/passkeys/reauth')
    expect(paths('sign-in-again')).not.toContain('/passkeys/reauth')
    expect(paths('password').filter((path) => path !== '/passkeys/reauth')).toEqual(
      paths('sign-in-again'),
    )
  })
})
