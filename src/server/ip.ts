import type { PayloadRequest } from 'payload'

import { isIP } from 'net'

/** A host's own way to find the caller's IP (the `clientIp` option). */
export type ClientIpResolver = (req: PayloadRequest) => null | string | undefined

/** The rightmost `x-forwarded-for` entry: the one the nearest proxy appended, not the client. */
export const rightmostForwardedFor = (req: Pick<PayloadRequest, 'headers'>): null | string =>
  req.headers.get('x-forwarded-for')?.split(',').at(-1) ?? null

/**
 * The caller's IP: the host's `clientIp` resolver if set, else the rightmost `x-forwarded-for`
 * entry. Anything that isn't an IP address is null. `x-real-ip` and the leftmost entries are
 * whatever the client sent unless a proxy replaced them, so they are not read by default (README).
 */
export const clientIp = (
  req: PayloadRequest,
  resolve: ClientIpResolver = rightmostForwardedFor,
): null | string => {
  const ip = resolve(req)?.trim()
  return ip && isIP(ip) !== 0 ? ip : null
}

const expandIPv6 = (ip: string): null | string[] => {
  const [head = '', tail = ''] = ip.split('::')
  const left = head ? head.split(':') : []
  const right = ip.includes('::') ? (tail ? tail.split(':') : []) : []
  const fill = ip.includes('::') ? 8 - left.length - right.length : 0
  const groups = [...left, ...Array<string>(Math.max(fill, 0)).fill('0'), ...right]
  return groups.length === 8 ? groups : null
}

/** An IP for a failure log line (review L1). Never call this on a success path. */
export const formatIp = (
  ip: null | string,
  mode: 'full' | 'none' | 'truncated',
): string | undefined => {
  if (!ip || mode === 'none') return undefined
  const mapped = ip.startsWith('::ffff:') && isIP(ip.slice(7)) === 4 ? ip.slice(7) : ip
  const version = isIP(mapped)
  if (version === 0) return undefined
  if (mode === 'full') return mapped
  if (version === 4) return `${mapped.split('.').slice(0, 3).join('.')}.0/24`
  const groups = expandIPv6(mapped)
  if (!groups) return undefined
  return `${groups
    .slice(0, 3)
    .map((g) => g.replace(/^0+(?=.)/, ''))
    .join(':')}::/48`
}
