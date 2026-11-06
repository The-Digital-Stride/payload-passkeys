import type { Endpoint, PayloadRequest, TypedUser } from 'payload'

import { addDataAndFileToRequest, headersWithCors } from 'payload'
import { parseCookies } from 'payload/shared'

import type { PasskeysErrorCode } from '../shared/constants.js'
import type { PasskeyAction } from '../types.js'
import type { ResolvedOptions } from './options.js'

import { allowedByRateLimit } from './rateLimit.js'

/** Registration responses are a few KB; anything bigger is not a WebAuthn response. */
export const MAX_BODY_BYTES = 64 * 1024

export class EndpointError extends Error {
  readonly code: PasskeysErrorCode
  readonly status: number
  constructor(status: number, code: PasskeysErrorCode) {
    super(code)
    this.name = 'EndpointError'
    this.code = code
    this.status = status
  }
}

export const json = (
  req: PayloadRequest,
  status: number,
  body: unknown,
  setCookies: string[] = [],
): Response => {
  const headers = headersWithCors({
    headers: new Headers({ 'Cache-Control': 'no-store', 'Content-Type': 'application/json' }),
    req,
  })
  for (const line of setCookies) headers.append('Set-Cookie', line)
  return new Response(JSON.stringify(body), { headers, status })
}

/**
 * The JSON body, or a refusal. Exactly `application/json` before any `;`, the same test Payload's
 * parser uses, so multipart and its `_payload` field never reach an endpoint (review M4).
 */
export const readJsonBody = async (req: PayloadRequest): Promise<Record<string, unknown>> => {
  const [type = ''] = (req.headers.get('Content-Type') ?? '').split(';', 1)
  if (type.trim() !== 'application/json') throw new EndpointError(415, 'unsupported_media_type')
  if (Number(req.headers.get('Content-Length') ?? 0) > MAX_BODY_BYTES)
    throw new EndpointError(413, 'bad_request')
  try {
    await addDataAndFileToRequest(req)
  } catch {
    throw new EndpointError(400, 'bad_request')
  }
  const data: unknown = req.data ?? {}
  if (!data || typeof data !== 'object' || Array.isArray(data))
    throw new EndpointError(400, 'bad_request')
  return data as Record<string, unknown>
}

/** Origin in the configured list, or, with no Origin header, Sec-Fetch-Site: same-origin (M4). */
export const originAllowed = (req: Pick<PayloadRequest, 'headers'>, origins: string[]): boolean => {
  const origin = req.headers.get('Origin')
  if (origin !== null) return origins.includes(origin)
  return req.headers.get('Sec-Fetch-Site') === 'same-origin'
}

export type SignedInUser = TypedUser & {
  _sid: string
  _strategy: 'local-jwt'
  collection: string
  id: number | string
}

/**
 * A cookie session of this collection (L2). API keys and other strategies are refused, and so is
 * a JWT sent in the Authorization header: Payload's extractJWT reads the header before the cookie,
 * so a header token would otherwise pass as `local-jwt` with a `sid`.
 */
export const requireSignedIn = (
  req: Pick<PayloadRequest, 'headers' | 'payload' | 'user'>,
  collectionSlug: string,
): SignedInUser => {
  const user = req.user as (Partial<SignedInUser> & Record<string, unknown>) | null
  if (!user || user.collection !== collectionSlug) throw new EndpointError(401, 'unauthorised')
  const cookieName = `${req.payload.config.cookiePrefix}-token`
  if (
    user._strategy !== 'local-jwt' ||
    typeof user._sid !== 'string' ||
    !user._sid ||
    req.headers.get('Authorization') !== null ||
    !parseCookies(req.headers).get(cookieName)
  ) {
    throw new EndpointError(403, 'unauthorised')
  }
  return user as SignedInUser
}

export type HandlerArgs<A extends 'anonymous' | 'optional' | 'signed-in'> = {
  body: Record<string, unknown>
  collectionSlug: string
  options: ResolvedOptions
  req: PayloadRequest
  user: A extends 'signed-in' ? SignedInUser : null | SignedInUser
}

export const passkeyEndpoint = <A extends 'anonymous' | 'optional' | 'signed-in'>({
  action,
  auth,
  checkOrigin = true,
  collectionSlug,
  handler,
  options,
  path,
}: {
  action: PasskeyAction
  auth: A
  /** `status` alone skips it: it reports an origin mismatch instead of refusing. */
  checkOrigin?: boolean
  collectionSlug: string
  handler: (args: HandlerArgs<A>) => Promise<Response>
  options: ResolvedOptions
  path: string
}): Endpoint => ({
  handler: async (req) => {
    try {
      const body = await readJsonBody(req)
      if (checkOrigin && !originAllowed(req, options.origins))
        throw new EndpointError(403, 'forbidden_origin')
      let user: null | SignedInUser = null
      if (auth === 'signed-in') user = requireSignedIn(req, collectionSlug)
      if (auth === 'optional') {
        try {
          user = requireSignedIn(req, collectionSlug)
        } catch {
          user = null
        }
      }
      const allowed = await allowedByRateLimit({
        action,
        collectionSlug,
        options,
        req,
        userId: user?.id,
      })
      if (!allowed) throw new EndpointError(429, 'rate_limited')
      return await handler({ body, collectionSlug, options, req, user } as HandlerArgs<A>)
    } catch (error) {
      if (error instanceof EndpointError) return json(req, error.status, { error: error.code })
      req.payload.logger.error({ err: error, msg: `passkeys: ${path} failed` })
      return json(req, 500, { error: 'server_error' })
    }
  },
  method: 'post',
  path,
})
