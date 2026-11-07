import { describe, expect, it } from 'vitest'

import { clientIp, formatIp } from '../../src/server/ip.js'

const headers = (h: Record<string, string>) => ({ headers: new Headers(h) }) as never

describe('clientIp', () => {
  it('takes the rightmost x-forwarded-for entry, the one the nearest proxy appended', () => {
    expect(clientIp(headers({ 'x-forwarded-for': '6.6.6.6, 203.0.113.9' }))).toBe('203.0.113.9')
    expect(clientIp(headers({ 'x-forwarded-for': '198.51.100.1' }))).toBe('198.51.100.1')
    expect(clientIp(headers({ 'x-forwarded-for': ' 2001:db8::1 ' }))).toBe('2001:db8::1')
    expect(clientIp(headers({}))).toBeNull()
  })

  it('ignores a client-sent x-real-ip by default', () => {
    expect(clientIp(headers({ 'x-forwarded-for': '203.0.113.9', 'x-real-ip': '6.6.6.6' }))).toBe(
      '203.0.113.9',
    )
    expect(clientIp(headers({ 'x-real-ip': '6.6.6.6' }))).toBeNull()
  })

  it('uses the host override when given', () => {
    const fromRealIp = (req: { headers: Headers }) => req.headers.get('x-real-ip')
    expect(
      clientIp(headers({ 'x-forwarded-for': '6.6.6.6', 'x-real-ip': '203.0.113.9' }), fromRealIp),
    ).toBe('203.0.113.9')
    expect(clientIp(headers({ 'x-forwarded-for': '6.6.6.6' }), () => undefined)).toBeNull()
  })

  it('yields null for anything that is not an IP address', () => {
    expect(clientIp(headers({ 'x-forwarded-for': '203.0.113.9, unknown' }))).toBeNull()
    expect(clientIp(headers({ 'x-forwarded-for': '203.0.113.9,' }))).toBeNull()
    expect(clientIp(headers({ 'x-forwarded-for': 'ip:evil' }))).toBeNull()
    expect(clientIp(headers({}), () => 'not an ip')).toBeNull()
    expect(clientIp(headers({}), () => '203.0.113.9:443')).toBeNull()
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
