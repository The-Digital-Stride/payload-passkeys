import type { PayloadRequest } from 'payload'

import { isIP } from 'net'

/**
 * The caller's IP from proxy headers. Only meaningful behind a proxy that sets these itself
 * (Vercel, Cloudflare, a configured load balancer); otherwise the client chooses it (README).
 */
export const clientIp = (req: Pick<PayloadRequest, 'headers'>): null | string => {
  const real = req.headers.get('x-real-ip')?.trim()
  if (real) return real
  const forwarded = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
  return forwarded || null
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
