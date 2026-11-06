import { describe, expect, it } from 'vitest'

import {
  browserKeyCookie,
  browserKeyCookieName,
  clearBrowserKeyCookie,
} from '../../src/server/cookies.js'

describe('browser-key cookies (review L7)', () => {
  it('use __Host- and Secure only for https origins, one name per ceremony and collection', () => {
    expect(browserKeyCookieName('authentication', 'users', true)).toBe(
      '__Host-payload-passkeys-auth-users',
    )
    expect(browserKeyCookieName('registration', 'users', false)).toBe('payload-passkeys-reg-users')
  })
  it('are HttpOnly, SameSite=Strict, Path=/, no Domain, Max-Age=300', () => {
    const line = browserKeyCookie('__Host-payload-passkeys-auth-users', 'k', true)
    expect(line).toBe(
      '__Host-payload-passkeys-auth-users=k; Path=/; Max-Age=300; HttpOnly; SameSite=Strict; Secure',
    )
    expect(line).not.toMatch(/Domain/i)
    expect(clearBrowserKeyCookie('payload-passkeys-reg-users', false)).toBe(
      'payload-passkeys-reg-users=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict',
    )
  })
})
