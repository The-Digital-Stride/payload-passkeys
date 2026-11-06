import { describe, expect, it } from 'vitest'

import { clientIp, formatIp } from '../../src/server/ip.js'

const headers = (h: Record<string, string>) => ({ headers: new Headers(h) }) as never

describe('clientIp', () => {
  it('prefers x-real-ip, then the first x-forwarded-for entry', () => {
    expect(
      clientIp(headers({ 'x-real-ip': '203.0.113.9', 'x-forwarded-for': '198.51.100.1' })),
    ).toBe('203.0.113.9')
    expect(clientIp(headers({ 'x-forwarded-for': '198.51.100.1, 10.0.0.1' }))).toBe('198.51.100.1')
    expect(clientIp(headers({}))).toBeNull()
  })
})

describe('formatIp', () => {
  it('truncates IPv4 to /24 and IPv6 to /48', () => {
    expect(formatIp('203.0.113.9', 'truncated')).toBe('203.0.113.0/24')
    expect(formatIp('2001:db8:85a3:8d3:1319:8a2e:370:7348', 'truncated')).toBe('2001:db8:85a3::/48')
    expect(formatIp('2001:db8::1', 'truncated')).toBe('2001:db8:0::/48')
    expect(formatIp('::ffff:203.0.113.9', 'truncated')).toBe('203.0.113.0/24')
  })
  it('honours none and full', () => {
    expect(formatIp('203.0.113.9', 'none')).toBeUndefined()
    expect(formatIp('203.0.113.9', 'full')).toBe('203.0.113.9')
    expect(formatIp(null, 'full')).toBeUndefined()
    expect(formatIp('garbage', 'truncated')).toBeUndefined()
  })
})
