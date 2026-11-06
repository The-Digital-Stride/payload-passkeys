import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import type { PasskeyAction } from '../../src/types.js'

import { ENDPOINTS } from '../../src/shared/constants.js'
import config, { limiter } from '../configs/throwingRateLimit.js'
import { createClient } from '../helpers/api.js'
import { passwordClient } from '../helpers/ceremonies.js'
import { createUser } from '../helpers/users.js'

/** Every endpoint asks the host's rateLimit hook, and anything but `true` refuses (fail closed). */

let payload: Payload
let user: Awaited<ReturnType<typeof createUser>>
beforeAll(async () => {
  payload = await getPayload({ config })
  user = await createUser(payload, 'users')
})
afterAll(async () => {
  await payload.destroy()
})

const throwing = () => {
  throw new Error('limiter down')
}
beforeEach(() => {
  limiter.calls.length = 0
  limiter.impl = throwing
})

const ACTIONS: Record<(typeof ENDPOINTS)[keyof typeof ENDPOINTS], PasskeyAction> = {
  [ENDPOINTS.delete]: 'delete',
  [ENDPOINTS.reauth]: 'reauth',
  [ENDPOINTS.registerOptions]: 'register.options',
  [ENDPOINTS.registerVerify]: 'register.verify',
  [ENDPOINTS.rename]: 'rename',
  [ENDPOINTS.signInOptions]: 'sign-in.options',
  [ENDPOINTS.signInVerify]: 'sign-in.verify',
  [ENDPOINTS.status]: 'status',
}
const SIGNED_IN = new Set<string>([
  ENDPOINTS.delete,
  ENDPOINTS.reauth,
  ENDPOINTS.registerOptions,
  ENDPOINTS.registerVerify,
  ENDPOINTS.rename,
])

const call = async (endpoint: string) => {
  const client = SIGNED_IN.has(endpoint)
    ? await passwordClient(config, 'users', user.email)
    : createClient(config)
  return client.post(`/api/users${endpoint}`, {
    id: 'x',
    name: 'x',
    password: 'x',
  })
}

describe('rate limiting fails closed', () => {
  it.each(Object.values(ENDPOINTS))('%s answers 429 when the hook throws', async (endpoint) => {
    const res = await call(endpoint)
    expect(res.status).toBe(429)
    expect(res.json).toEqual({ error: 'rate_limited' })
    expect(limiter.calls.map((c) => c.action)).toEqual([ACTIONS[endpoint]])
    const [args] = limiter.calls
    expect(args).toMatchObject({ collection: 'users' })
    if (SIGNED_IN.has(endpoint)) {
      expect(args!.key).toBe(`users:${String(user.id)}`)
      expect(args!.userId).toBe(user.id)
    } else {
      expect(args!.key).toMatch(/^ip:/)
      expect(args!.userId).toBeUndefined()
    }
  })

  it.each([
    ['rejects', () => Promise.reject(new Error('limiter down'))],
    ['returns false', () => false],
    ['returns undefined', () => undefined],
    ['returns a truthy non-boolean', () => 'true'],
    ['resolves to 1', () => Promise.resolve(1)],
  ])('refuses when the hook %s', async (_label, impl) => {
    limiter.impl = impl
    const res = await call(ENDPOINTS.signInOptions)
    expect(res.status).toBe(429)
    expect(res.json).toEqual({ error: 'rate_limited' })
  })

  it('goes ahead only when the hook returns true', async () => {
    limiter.impl = () => true
    expect((await call(ENDPOINTS.signInOptions)).status).toBe(200)
    limiter.impl = () => Promise.resolve(true)
    expect((await call(ENDPOINTS.signInOptions)).status).toBe(200)
  })

  it('does not stand in front of password sign-in', async () => {
    const res = await createClient(config).post('/api/users/login', {
      email: user.email,
      password: 'correct horse battery staple',
    })
    expect(res.status).toBe(200)
    expect(limiter.calls).toEqual([])
  })
})
