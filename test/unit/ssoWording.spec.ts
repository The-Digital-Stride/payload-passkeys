import { describe, expect, it } from 'vitest'

import { sessionMayRemain, signInAgainUrl } from '../../src/components/shared/signInAgain.js'
import { keyForMode, SSO_KEYS } from '../../src/shared/ssoKeys.js'
import { en } from '../../src/translations/en.js'
import { withPasskeysTranslations } from '../../src/translations/index.js'

const merged = (passkeys?: Record<string, string>) =>
  (
    withPasskeysTranslations(
      passkeys ? { translations: { en: { passkeys } } as never } : undefined,
    )!.translations as unknown as Record<string, { passkeys: Record<string, string> }>
  ).en!.passkeys

describe('host overrides of SSO wording', () => {
  it('(a) an override of only the base key reaches the Sso key', () => {
    const passkeys = merged({ sectionDescription: 'Mine' })
    expect(passkeys.sectionDescription).toBe('Mine')
    expect(passkeys.sectionDescriptionSso).toBe('Mine')
    expect(passkeys.busySso).toBe(en.passkeys.busySso)
  })

  it('(b) overriding both keeps each text', () => {
    const passkeys = merged({ sectionDescription: 'Base', sectionDescriptionSso: 'Neutral' })
    expect(passkeys.sectionDescription).toBe('Base')
    expect(passkeys.sectionDescriptionSso).toBe('Neutral')
  })

  it('(c) with no override the English Sso text is used', () => {
    expect(merged().sectionDescriptionSso).toBe(en.passkeys.sectionDescriptionSso)
    expect(merged({ unrelated: 'x' }).busySso).toBe(en.passkeys.busySso)
  })
})

describe('keyForMode', () => {
  it.each([...SSO_KEYS])('(d) picks the Sso sibling of %s only in sign-in-again mode', (key) => {
    expect(keyForMode(key, 'sign-in-again')).toBe(`${key}Sso`)
    expect(keyForMode(key, 'password')).toBe(key)
  })

  it('(d) leaves other keys alone', () => {
    expect(keyForMode('addPasskey', 'sign-in-again')).toBe('addPasskey')
  })
})

describe('signInAgainUrl', () => {
  const url = (current: string, adminRoute = '/admin', loginRoute?: string) =>
    signInAgainUrl({ adminRoute, current, loginRoute })

  it('sends the current admin page as redirect', () => {
    expect(url('/admin/account?x=1')).toBe(
      `/admin/login?redirect=${encodeURIComponent('/admin/account?x=1')}`,
    )
  })

  it('works with the admin at the root', () => {
    expect(url('/account', '/')).toBe(`/login?redirect=${encodeURIComponent('/account')}`)
  })

  it('uses a custom login route, with or without a leading slash', () => {
    expect(url('/admin/account', '/admin', '/sign-in')).toBe(
      `/admin/sign-in?redirect=${encodeURIComponent('/admin/account')}`,
    )
    expect(url('/admin/account', '/admin', 'sign-in')).toContain('/admin/sign-in?')
  })

  it.each(['/elsewhere', '//evil.example', 'https://evil.example/admin', '/admin/../x'])(
    'falls back to the admin for %s',
    (current) => {
      expect(url(current)).toBe(`/admin/login?redirect=${encodeURIComponent('/admin')}`)
    },
  )
})

describe('sessionMayRemain', () => {
  it.each([400, 401, 403])('treats %i as already signed out', (status) => {
    expect(sessionMayRemain(status)).toBe(false)
  })
  it.each([0, 500, 502, 503])('keeps the error for %i', (status) => {
    expect(sessionMayRemain(status)).toBe(true)
  })
})
