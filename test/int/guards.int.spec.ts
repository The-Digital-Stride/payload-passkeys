import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import type { ApiResult } from '../helpers/api.js'

import { MAX_BODY_BYTES } from '../../src/server/http.js'
import { ENDPOINTS } from '../../src/shared/constants.js'
import config from '../configs/single.js'
import { createClient, SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey, signInWithPasskey } from '../helpers/ceremonies.js'
import { findSecretKeys } from '../helpers/secrets.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, PASSWORD, rawUser } from '../helpers/users.js'

/**
 * Reviews M1, M4 and L2: no plugin response carries a secret, and every endpoint enforces its
 * guards (JSON only, bounded body, configured origin, cookie session). The fail-closed rate-limit
 * hook needs its own Payload instance, so it lives in guards.rateLimit.int.spec.ts.
 */

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const all = Object.values(ENDPOINTS)
const notStatus = all.filter((endpoint) => endpoint !== ENDPOINTS.status)
const ceremonies = [
  ENDPOINTS.registerOptions,
  ENDPOINTS.registerVerify,
  ENDPOINTS.signInOptions,
  ENDPOINTS.signInVerify,
]
const signedIn = [
  ENDPOINTS.registerOptions,
  ENDPOINTS.registerVerify,
  ENDPOINTS.reauth,
  ENDPOINTS.rename,
  ENDPOINTS.delete,
]
const path = (endpoint: string) => `/api/users${endpoint}`

describe('no plugin response contains a secret (review M1)', () => {
  it('across a full lifecycle, failures included', async () => {
    const apiKey = crypto.randomUUID()
    const user = await createUser(payload, 'users', { apiKey, enableAPIKey: true })
    const client = await passwordClient(config, 'users', user.email)
    const authenticator = createSoftAuthenticator({ origin: SERVER_URL })
    const seen: { body: unknown; label: string }[] = []
    const see = (label: string, res: ApiResult | null) => {
      expect(res, label).not.toBeNull()
      seen.push({ body: res!.json, label })
      return res!
    }

    const { options, verify } = await registerPasskey(client, authenticator)
    see('register/options', options)
    see('register/verify', verify)
    expect(verify!.status).toBe(200)
    const refusedRegistration = await registerPasskey(
      client,
      createSoftAuthenticator({ origin: SERVER_URL }),
      { overrides: { userVerified: false } },
    )
    see('register/verify refused', refusedRegistration.verify)

    const signIn = await signInWithPasskey(createClient(config), authenticator)
    see('sign-in/options', signIn.options)
    expect(see('sign-in/verify', signIn.verify).status).toBe(200)
    see(
      'sign-in/verify refused',
      (
        await signInWithPasskey(createClient(config), authenticator, {
          overrides: { badSignature: true },
        })
      ).verify,
    )

    const status = see('status signed in', await client.post(path(ENDPOINTS.status)))
    see('status anonymous', await createClient(config).post(path(ENDPOINTS.status)))
    see('reauth refused', await client.post(path(ENDPOINTS.reauth), { password: 'wrong' }))
    expect(
      see('reauth', await client.post(path(ENDPOINTS.reauth), { password: PASSWORD })).status,
    ).toBe(200)
    const id = verify!.json.passkey.id
    see('rename', await client.post(path(ENDPOINTS.rename), { id, name: 'Renamed' }))
    see('rename refused', await client.post(path(ENDPOINTS.rename), { id: 'nope', name: 'x' }))
    expect(see('delete', await client.post(path(ENDPOINTS.delete), { id })).status).toBe(200)

    for (const { body, label } of seen) {
      expect(findSecretKeys(body), label).toEqual([])
      expect(JSON.stringify(body), label).not.toMatch(/"(hash|salt|userHandle)"/)
    }

    // The values themselves, wherever they might hide (a renamed key, a nested string).
    const raw = await rawUser(payload, 'users', user.id)
    const handle = raw.passkeyUserHandle as string
    const secrets = [apiKey, raw.hash, raw.salt, raw.apiKeyIndex].filter(
      (value): value is string => typeof value === 'string' && value.length > 0,
    )
    expect(secrets.length).toBeGreaterThanOrEqual(3)
    for (const { body, label } of seen) {
      const text = JSON.stringify(body)
      for (const secret of secrets) expect(text.includes(secret), label).toBe(false)
      // The WebAuthn user ID goes to the signed-in owner only: as user.id in their own creation
      // options (the authenticator must store it) and as status's signalUserId. Nowhere else.
      if (label === 'register/options') {
        const { options: creation } = body as { options: { user: { id: string } } }
        expect(creation.user.id).toBe(handle)
        expect(text.split(handle).length - 1, label).toBe(1)
      } else if (label !== 'status signed in') {
        expect(text.includes(handle), label).toBe(false)
      }
    }
    expect(status.json.signalUserId).toBe(handle)
  })
})

describe('content type (review M4)', () => {
  it.each(all)('%s refuses multipart with a _payload field', async (endpoint) => {
    const res = await createClient(config).post(
      path(endpoint),
      '--x\r\nContent-Disposition: form-data; name="_payload"\r\n\r\n{}\r\n--x--\r\n',
      { contentType: 'multipart/form-data; boundary=x' },
    )
    expect(res.status).toBe(415)
    expect(res.json).toEqual({ error: 'unsupported_media_type' })
  })

  it.each(all)('%s refuses text/plain', async (endpoint) => {
    const res = await createClient(config).post(path(endpoint), '{}', { contentType: 'text/plain' })
    expect(res.status).toBe(415)
  })

  it.each(all)('%s refuses an HTML form body', async (endpoint) => {
    const res = await createClient(config).post(path(endpoint), '_payload=%7B%7D', {
      contentType: 'application/x-www-form-urlencoded',
    })
    expect(res.status).toBe(415)
  })

  it('refuses JSON that is not an object, or not JSON', async () => {
    for (const body of ['[]', '"x"', 'null', '{"a":', 'not json']) {
      const res = await createClient(config).post(path(ENDPOINTS.signInOptions), body, {
        contentType: 'application/json',
      })
      expect(res.status, body).toBe(400)
      expect(res.json, body).toEqual({ error: 'bad_request' })
    }
  })
})

describe('body size', () => {
  it.each(all)('%s refuses a body over 64 KB with 413', async (endpoint) => {
    const res = await createClient(config).post(path(endpoint), {
      pad: 'x'.repeat(MAX_BODY_BYTES + 1),
    })
    expect(res.status).toBe(413)
    expect(res.json).toEqual({ error: 'bad_request' })
  })

  it('accepts a body just under the limit', async () => {
    const res = await createClient(config).post(path(ENDPOINTS.signInOptions), {
      pad: 'x'.repeat(MAX_BODY_BYTES - 64),
    })
    expect(res.status).toBe(200)
  })
})

describe('origin (review M4)', () => {
  it.each(notStatus)('%s refuses a foreign Origin', async (endpoint) => {
    const res = await createClient(config, { origin: 'https://evil.test' }).post(path(endpoint))
    expect(res.status).toBe(403)
    expect(res.json).toEqual({ error: 'forbidden_origin' })
  })

  it.each(notStatus)(
    "%s refuses an origin in Payload's csrf list but not in the plugin's origins",
    async (endpoint) => {
      const res = await createClient(config, { origin: 'http://127.0.0.1:3000' }).post(
        path(endpoint),
      )
      expect(res.status).toBe(403)
    },
  )

  it.each(notStatus)('%s refuses the opaque Origin "null"', async (endpoint) => {
    expect((await createClient(config, { origin: 'null' }).post(path(endpoint))).status).toBe(403)
  })

  it.each(notStatus)(
    '%s refuses a request with no Origin and no Sec-Fetch-Site',
    async (endpoint) => {
      expect((await createClient(config, { origin: null }).post(path(endpoint))).status).toBe(403)
    },
  )

  it.each(ceremonies)(
    '%s refuses no Origin with Sec-Fetch-Site cross-site or same-site',
    async (endpoint) => {
      for (const site of ['cross-site', 'same-site', 'none']) {
        const res = await createClient(config, { origin: null }).post(
          path(endpoint),
          {},
          { headers: { 'Sec-Fetch-Site': site } },
        )
        expect(res.status, site).toBe(403)
      }
    },
  )

  it('accepts no Origin with Sec-Fetch-Site: same-origin', async () => {
    const anonymous = createClient(config, { origin: null })
    const sameOrigin = { headers: { 'Sec-Fetch-Site': 'same-origin' } }
    expect((await anonymous.post(path(ENDPOINTS.signInOptions), {}, sameOrigin)).status).toBe(200)

    const user = await createUser(payload, 'users')
    const signedInClient = await passwordClient(config, 'users', user.email)
    const noOrigin = createClient(config, { origin: null })
    for (const [name, value] of signedInClient.cookies) noOrigin.cookies.set(name, value)
    const res = await noOrigin.post(path(ENDPOINTS.registerOptions), {}, sameOrigin)
    expect(res.status).toBe(200)
    expect(res.json.options.challenge).toEqual(expect.any(String))
  })

  it('status answers a foreign origin anonymously, saying only that passkeys are unavailable', async () => {
    const res = await createClient(config, { origin: 'https://evil.test' }).post(
      path(ENDPOINTS.status),
    )
    expect(res.status).toBe(200)
    expect(res.json).toEqual({ available: false })
    expect(
      (await createClient(config, { origin: null }).post(path(ENDPOINTS.status))).json,
    ).toEqual({ available: false })
  })

  it("status gives a foreign origin no detail even with the owner's cookie", async () => {
    const user = await createUser(payload, 'users')
    const owner = await passwordClient(config, 'users', user.email)
    const res = await owner.post(
      path(ENDPOINTS.status),
      {},
      { headers: { Origin: 'https://evil.test' } },
    )
    expect(res.json).toEqual({ available: false })
  })
})

describe('session kind (review L2)', () => {
  it.each(signedIn)('%s refuses an API key, a header JWT and a Bearer token', async (endpoint) => {
    const apiKey = crypto.randomUUID()
    const user = await createUser(payload, 'users', { apiKey, enableAPIKey: true })
    // The key really authenticates with Payload, so the refusal below is the plugin's.
    const me = await createClient(config).get('/api/users/me', {
      headers: { Authorization: `users API-Key ${apiKey}` },
    })
    expect(me.json.user.id).toBe(user.id)
    const viaApiKey = await createClient(config).post(
      path(endpoint),
      {},
      { headers: { Authorization: `users API-Key ${apiKey}` } },
    )
    expect(viaApiKey.status).toBe(403)
    expect(viaApiKey.json).toEqual({ error: 'unauthorised' })

    const login = await createClient(config).post('/api/users/login', {
      email: user.email,
      password: PASSWORD,
    })
    const token = login.json.token as string
    expect(token).toEqual(expect.any(String))
    for (const scheme of ['JWT', 'Bearer']) {
      const headerMe = await createClient(config).get('/api/users/me', {
        headers: { Authorization: `${scheme} ${token}` },
      })
      expect(headerMe.json.user.id, scheme).toBe(user.id)
      const res = await createClient(config).post(
        path(endpoint),
        {},
        { headers: { Authorization: `${scheme} ${token}` } },
      )
      expect(res.status, scheme).toBe(403)
      expect(res.json, scheme).toEqual({ error: 'unauthorised' })
    }

    // A real cookie session plus any Authorization header is still refused.
    const withCookie = await passwordClient(config, 'users', user.email)
    for (const authorization of [`users API-Key ${apiKey}`, `JWT ${token}`]) {
      const both = await withCookie.post(
        path(endpoint),
        {},
        { headers: { Authorization: authorization } },
      )
      expect(both.status, authorization).toBe(403)
    }

    // A header JWT beside a junk session cookie: the header is what authenticates, so the
    // Authorization-header check is the only guard here.
    const junkCookie = createClient(config)
    junkCookie.cookies.set('payload-token', 'junk')
    const junk = await junkCookie.post(
      path(endpoint),
      {},
      { headers: { Authorization: `JWT ${token}` } },
    )
    expect(junk.status).toBe(403)
    expect(junk.json).toEqual({ error: 'unauthorised' })
  })

  it.each(signedIn)('%s refuses an anonymous caller with 401', async (endpoint) => {
    const res = await createClient(config).post(path(endpoint))
    expect(res.status).toBe(401)
    expect(res.json).toEqual({ error: 'unauthorised' })
  })

  it('status treats an API key as anonymous', async () => {
    const apiKey = crypto.randomUUID()
    await createUser(payload, 'users', { apiKey, enableAPIKey: true })
    const res = await createClient(config).post(
      path(ENDPOINTS.status),
      {},
      { headers: { Authorization: `users API-Key ${apiKey}` } },
    )
    expect(res.json).toEqual({ available: true })
  })
})
