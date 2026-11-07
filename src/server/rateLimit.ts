import type { PayloadRequest } from 'payload'

import type { PasskeyAction } from '../types.js'
import type { ResolvedOptions } from './options.js'

/**
 * True to go ahead. A throw from the `clientIp` resolver or the `rateLimit` hook, or anything but
 * `true` from the hook, refuses with 429 (fail closed).
 */
export const allowedByRateLimit = async ({
  action,
  collectionSlug,
  options,
  req,
  userId,
}: {
  action: PasskeyAction
  collectionSlug: string
  options: Pick<ResolvedOptions, 'clientIp' | 'rateLimit'>
  req: PayloadRequest
  userId?: number | string
}): Promise<boolean> => {
  let ip: null | string
  try {
    ip = options.clientIp(req)
  } catch (error) {
    req.payload.logger.error({
      err: error,
      msg: 'passkeys: the clientIp resolver threw; refusing the request',
    })
    return false
  }
  const key = userId === undefined ? `ip:${ip ?? 'unknown'}` : `${collectionSlug}:${String(userId)}`
  try {
    return (
      (await options.rateLimit({ action, collection: collectionSlug, ip, key, req, userId })) ===
      true
    )
  } catch (error) {
    req.payload.logger.error({
      err: error,
      msg: 'passkeys: the rateLimit hook threw; refusing the request',
    })
    return false
  }
}
