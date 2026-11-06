import { describe, expect, it } from 'vitest'

import {
  EndpointError,
  originAllowed,
  readJsonBody,
  requireSignedIn,
} from '../../src/server/http.js'

const req = (init: { body?: string; headers?: Record<string, string>; user?: unknown }) => {
  const request = new Request('http://localhost:3000/api/users/passkeys/x', {
    body: init.body,
    headers: init.headers,
    method: 'POST',
  })
  return Object.assign(request, {
    payload: { config: { cookiePrefix: 'payload' } },
    user: init.user ?? null,
  }) as never
}

describe('readJsonBody (review M4)', () => {
  it('parses an application/json object', async () => {
    expect(
      await readJsonBody(req({ body: '{"a":1}', headers: { 'Content-Type': 'application/json' } })),
    ).toEqual({ a: 1 })
    expect(
      await readJsonBody(
        req({ body: '{}', headers: { 'Content-Type': 'application/json; charset=utf-8' } }),
      ),
    ).toEqual({})
  })
  it.each([
    'multipart/form-data; boundary=x',
    'text/plain',
    'application/x-www-form-urlencoded',
    '',
  ])('refuses %j with 415', async (type) => {
    const error = await readJsonBody(
      req({ body: '_payload={}', headers: type ? { 'Content-Type': type } : {} }),
    ).catch((e) => e)
    expect(error).toBeInstanceOf(EndpointError)
    expect(error).toMatchObject({ code: 'unsupported_media_type', status: 415 })
  })
  it('refuses arrays, invalid JSON and large bodies with 400 or 413', async () => {
    const json = { 'Content-Type': 'application/json' }
    await expect(readJsonBody(req({ body: '[1]', headers: json }))).rejects.toMatchObject({
      status: 400,
    })
    await expect(readJsonBody(req({ body: '{', headers: json }))).rejects.toMatchObject({
      status: 400,
    })
    await expect(
      readJsonBody(req({ body: '{}', headers: { ...json, 'Content-Length': String(65 * 1024) } })),
    ).rejects.toMatchObject({ status: 413 })
  })

  it('stops reading a body with no Content-Length once it passes the limit', async () => {
    let sent = 0
    const chunk = new TextEncoder().encode(`{"a":"${'x'.repeat(16 * 1024)}`)
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        sent += chunk.byteLength
        controller.enqueue(chunk)
        if (sent > 1024 * 1024) controller.close()
      },
    })
    const request = new Request('http://localhost:3000/api/users/passkeys/x', {
      body,
      duplex: 'half',
      headers: { 'Content-Type': 'application/json' },
      method: 'POST',
    } as RequestInit)
    expect(request.headers.get('Content-Length')).toBeNull()
    const fake = Object.assign(request, { payload: { config: {} }, user: null }) as never
    await expect(readJsonBody(fake)).rejects.toMatchObject({ status: 413 })
    expect(sent).toBeLessThan(256 * 1024)
  })
})

describe('originAllowed (review M4)', () => {
  const origins = ['https://example.com']
  it('accepts a listed Origin, else Sec-Fetch-Site: same-origin', () => {
    expect(originAllowed(req({ headers: { Origin: 'https://example.com' } }), origins)).toBe(true)
    expect(originAllowed(req({ headers: { Origin: 'https://evil.test' } }), origins)).toBe(false)
    expect(originAllowed(req({ headers: { Origin: 'null' } }), origins)).toBe(false)
    expect(originAllowed(req({ headers: { 'Sec-Fetch-Site': 'same-origin' } }), origins)).toBe(true)
    expect(originAllowed(req({ headers: { 'Sec-Fetch-Site': 'same-site' } }), origins)).toBe(false)
    expect(originAllowed(req({ headers: {} }), origins)).toBe(false)
  })
})

describe('requireSignedIn (review L2)', () => {
  const cookie = { Cookie: 'payload-token=t' }
  const ok = { _sid: 's', _strategy: 'local-jwt', collection: 'users', id: 1 }
  it('accepts a cookie session of this collection', () => {
    expect(requireSignedIn(req({ headers: cookie, user: ok }), 'users')).toBe(ok)
  })
  it.each([
    ['no user', {}],
    ['another collection', { headers: cookie, user: { ...ok, collection: 'customers' } }],
    ['an API key', { headers: cookie, user: { ...ok, _strategy: 'api-key' } }],
    ['no session id', { headers: cookie, user: { ...ok, _sid: undefined } }],
    [
      'a JWT in the Authorization header',
      { headers: { ...cookie, Authorization: 'JWT t' }, user: ok },
    ],
    ['no session cookie', { headers: {}, user: ok }],
  ])('refuses %s', (_, init) => {
    expect(() => requireSignedIn(req(init as never), 'users')).toThrow(EndpointError)
  })
})
