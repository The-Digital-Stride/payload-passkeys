import type { PayloadRequest } from 'payload'

import type { ResolvedOptions } from './options.js'

import { formatIp } from './ip.js'

export type PasskeyEvent =
  | 'passkeys.counter_regression'
  | 'passkeys.reauth_failed'
  | 'passkeys.reauth_required'
  | 'passkeys.reauthenticated'
  | 'passkeys.registered'
  | 'passkeys.registration_failed'
  | 'passkeys.removed'
  | 'passkeys.renamed'
  | 'passkeys.sign_in_failed'
  | 'passkeys.signed_in'
  | 'passkeys.signed_in_while_locked'
  | 'passkeys.unknown_credential'

const FAILURES = new Set<PasskeyEvent>([
  'passkeys.reauth_failed',
  'passkeys.registration_failed',
  'passkeys.sign_in_failed',
  'passkeys.unknown_credential',
])

export type EventFields = {
  aaguid?: null | string
  collection: string
  credentialId?: string
  reason?: string
  userId?: number | string
}

/**
 * One structured line per event. Never challenges, signatures, public keys, user handles or
 * emails; a credential ID is cut to 8 characters; an IP only on failures and as `logging.ip` says.
 */
export const logEvent = (
  req: PayloadRequest,
  options: Pick<ResolvedOptions, 'clientIp' | 'logging'>,
  event: PasskeyEvent,
  { credentialId, ...fields }: EventFields,
): void => {
  const failure = FAILURES.has(event)
  const line: Record<string, unknown> = { event, ...fields }
  if (credentialId) line.credentialIdPrefix = credentialId.slice(0, 8)
  if (failure) {
    const ip = formatIp(options.clientIp(req), options.logging.ip)
    if (ip) line.ip = ip
  }
  const level = failure || event === 'passkeys.counter_regression' ? 'warn' : 'info'
  req.payload.logger[level]({ ...line, msg: event })
}
