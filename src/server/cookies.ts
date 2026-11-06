import type { PayloadRequest } from 'payload'

import { parseCookies } from 'payload/shared'

import { CHALLENGE_TTL_MS } from '../shared/constants.js'

export type CeremonyType = 'authentication' | 'registration'

/**
 * One cookie per ceremony type and collection, so two tabs (or a sign-in and a registration)
 * never overwrite each other. `__Host-` and Secure follow the configured origins' scheme, never
 * req.url, which reads http behind a TLS-terminating proxy (review L7).
 */
export const browserKeyCookieName = (
  type: CeremonyType,
  collection: string,
  secure: boolean,
): string =>
  `${secure ? '__Host-' : ''}payload-passkeys-${type === 'registration' ? 'reg' : 'auth'}-${collection}`

const attributes = (maxAge: number, secure: boolean): string =>
  `Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}`

export const browserKeyCookie = (name: string, value: string, secure: boolean): string =>
  `${name}=${value}; ${attributes(CHALLENGE_TTL_MS / 1000, secure)}`

export const clearBrowserKeyCookie = (name: string, secure: boolean): string =>
  `${name}=; ${attributes(0, secure)}`

export const readCookie = (
  req: Pick<PayloadRequest, 'headers'>,
  name: string,
): string | undefined => parseCookies(req.headers).get(name) || undefined
