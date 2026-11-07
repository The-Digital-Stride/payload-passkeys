import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import config from '../configs/single.js'
import { createClient } from '../helpers/api.js'
import { createUser, PASSWORD } from '../helpers/users.js'

let payload: Payload

beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

describe('harness', () => {
  it('answers /me anonymously', async () => {
    const me = await createClient(config).get('/api/users/me')
    expect(me.status).toBe(200)
    expect(me.json.user).toBeNull()
  })

  it('keeps the session cookie across calls', async () => {
    const user = await createUser(payload, 'users')
    const client = createClient(config)
    const login = await client.post('/api/users/login', { email: user.email, password: PASSWORD })
    expect(login.status).toBe(200)
    const me = await client.get('/api/users/me')
    expect(me.json.user.id).toBe(user.id)
  })
})
