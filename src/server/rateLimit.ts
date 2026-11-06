import type { PayloadRequest } from 'payload'

import type { PasskeyAction } from '../types.js'
import type { ResolvedOptions } from './options.js'

import { clientIp } from './ip.js'

/** True to go ahead. A throw, or anything but `true`, refuses with 429 (fail closed). */
export const allowedByRateLimit = async ({
  action,
  collectionSlug,
  options,
  req,
  userId,
}: {
  action: PasskeyAction
  collectionSlug: string
  options: Pick<ResolvedOptions, 'rateLimit'>
  req: PayloadRequest
  userId?: number | string
}): Promise<boolean> => {
  const ip = clientIp(req)
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
