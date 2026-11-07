import { describe, expect, it } from 'vitest'

import {
  isHostingPublicSuffix,
  isIpAddress,
  normaliseOrigin,
  originMatchesRpID,
  rpIDProblem,
} from '../../src/shared/rpid.js'

describe('rpIDProblem', () => {
  it.each(['example.com', 'admin.example.co.uk', 'localhost', 'my-site.vercel.app'])(
    'accepts %s',
    (rpID) => {
      expect(rpIDProblem(rpID)).toBeNull()
    },
  )
  it.each([
    ['vercel.app', 'public_suffix'],
    ['netlify.app', 'public_suffix'],
    ['pages.dev', 'public_suffix'],
    ['com', 'single_label'],
    ['127.0.0.1', 'ip_address'],
    ['[::1]', 'ip_address'],
    ['Example.com', 'not_lowercase'],
    ['example.com.', 'trailing_dot'],
    ['', 'empty'],
    ['https://example.com', 'not_a_hostname'],
  ])('refuses %s (%s)', (rpID, problem) => {
    expect(rpIDProblem(rpID)).toBe(problem)
  })
})

describe('normaliseOrigin', () => {
  it('returns scheme, host and port only', () => {
    expect(normaliseOrigin('https://example.com/')).toBe('https://example.com')
    expect(normaliseOrigin('https://example.com:8443')).toBe('https://example.com:8443')
    expect(normaliseOrigin('http://localhost:3000')).toBe('http://localhost:3000')
  })
  it.each([
    'https://example.com/admin',
    'https://example.com?x=1',
    'ftp://example.com',
    'http://example.com',
    'not a url',
  ])('refuses %s', (origin) => {
    expect(normaliseOrigin(origin)).toBeNull()
  })
})

describe('originMatchesRpID', () => {
  it('matches the RP ID itself and its subdomains only', () => {
    expect(originMatchesRpID('https://example.com', 'example.com')).toBe(true)
    expect(originMatchesRpID('https://www.example.com', 'example.com')).toBe(true)
    expect(originMatchesRpID('https://badexample.com', 'example.com')).toBe(false)
    expect(originMatchesRpID('https://example.com.evil.test', 'example.com')).toBe(false)
    expect(originMatchesRpID('https://site-git-x.vercel.app', 'example.com')).toBe(false)
    expect(originMatchesRpID('http://localhost:3000', 'localhost')).toBe(true)
    expect(originMatchesRpID('http://127.0.0.1:3000', 'localhost')).toBe(false)
  })
})

describe('helpers', () => {
  it('knows hosting suffixes and IP addresses', () => {
    expect(isHostingPublicSuffix('vercel.app')).toBe(true)
    expect(isHostingPublicSuffix('example.com')).toBe(false)
    expect(isIpAddress('10.0.0.1')).toBe(true)
    expect(isIpAddress('::1')).toBe(true)
    expect(isIpAddress('example.com')).toBe(false)
  })
})
