import type { SanitizedConfig } from 'payload'

import { handleEndpoints } from 'payload'

export const SERVER_URL = 'http://localhost:3000'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ApiResult<T = any> = { headers: Headers; json: T; status: number }

type RequestOptions = {
  body?: unknown
  /** Send the body raw with this content type instead of as JSON. */
  contentType?: string
  headers?: Record<string, string>
}

export type TestClient = {
  cookies: Map<string, string>
  delete: (path: string, options?: RequestOptions) => Promise<ApiResult>
  get: (path: string, options?: RequestOptions) => Promise<ApiResult>
  patch: (path: string, body?: unknown, options?: RequestOptions) => Promise<ApiResult>
  post: (path: string, body?: unknown, options?: RequestOptions) => Promise<ApiResult>
  request: (method: string, path: string, options?: RequestOptions) => Promise<ApiResult>
  /** Put a Set-Cookie line (as returned by mintSession) into the jar. */
  setCookie: (line: string) => void
}

const applySetCookie = (jar: Map<string, string>, line: string): void => {
  const [pair = '', ...attributes] = line.split(';')
  const index = pair.indexOf('=')
  if (index < 1) return
  const name = pair.slice(0, index).trim()
  const value = pair.slice(index + 1).trim()
  const expired = attributes.some((attribute) => {
    const [key = '', raw = ''] = attribute.trim().split('=')
    if (key.toLowerCase() === 'max-age') return Number(raw) <= 0
    if (key.toLowerCase() === 'expires') return Date.parse(raw) <= Date.now()
    return false
  })
  if (expired || value === '') jar.delete(name)
  else jar.set(name, value)
}

/**
 * Drives Payload's whole REST stack in-process (auth strategies, CSRF, plugin and core endpoints)
 * with a cookie jar. `origin: null` sends no Origin header.
 */
export const createClient = (
  config: Promise<SanitizedConfig> | SanitizedConfig,
  {
    origin = SERVER_URL,
    payloadKey,
  }: {
    origin?: null | string
    /** The getPayload cache key of a second Payload instance in the same process. */
    payloadKey?: string
  } = {},
): TestClient => {
  const cookies = new Map<string, string>()

  const request = async (method: string, path: string, options: RequestOptions = {}) => {
    const headers = new Headers(options.headers)
    if (origin && !headers.has('Origin')) headers.set('Origin', origin)
    let body: string | undefined
    if (options.body !== undefined) {
      body = typeof options.body === 'string' ? options.body : JSON.stringify(options.body)
      if (!headers.has('Content-Type'))
        headers.set('Content-Type', options.contentType ?? 'application/json')
    }
    if (cookies.size) {
      headers.set('Cookie', [...cookies].map(([name, value]) => `${name}=${value}`).join('; '))
    }
    const response = await handleEndpoints({
      config,
      payloadInstanceCacheKey: payloadKey,
      request: new Request(`${SERVER_URL}${path}`, { body, headers, method }),
    })
    for (const line of response.headers.getSetCookie()) applySetCookie(cookies, line)
    const text = await response.text()
    let json: unknown = null
    try {
      json = text ? JSON.parse(text) : null
    } catch {
      json = text
    }
    return { headers: response.headers, json, status: response.status } as ApiResult
  }

  return {
    cookies,
    delete: (path, options) => request('DELETE', path, options),
    get: (path, options) => request('GET', path, options),
    patch: (path, body, options) => request('PATCH', path, { ...options, body }),
    post: (path, body, options) => request('POST', path, { ...options, body: body ?? {} }),
    request,
    setCookie: (line) => applySetCookie(cookies, line),
  }
}

/** A new client that carries only the given cookies (to replay an old token after logout). */
export const cloneWithCookies = (
  config: Promise<SanitizedConfig> | SanitizedConfig,
  cookies: Map<string, string>,
): TestClient => {
  const client = createClient(config)
  for (const [name, value] of cookies) client.cookies.set(name, value)
  return client
}
