import { describe, expect, it } from 'vitest'

import type { Config } from 'payload'

import { passkeysPlugin } from '../../src/index.js'
import { SSO_KEYS } from '../../src/shared/ssoKeys.js'
import { en } from '../../src/translations/en.js'
import { withPasskeysTranslations } from '../../src/translations/index.js'

describe('withPasskeysTranslations', () => {
  it('adds English when the host configures nothing', () => {
    expect(withPasskeysTranslations(undefined)?.translations).toEqual({ en })
  })

  it('copies English into every supported or translated language, under host overrides', () => {
    const i18n = withPasskeysTranslations({
      supportedLanguages: { de: {} as never, en: {} as never },
      translations: {
        de: { passkeys: { signInWithPasskey: 'Mit Passkey anmelden' } },
        fr: { general: { x: 'y' } },
      } as never,
    })
    const translations = i18n!.translations as Record<string, { passkeys: Record<string, string> }>
    expect(translations.de!.passkeys.signInWithPasskey).toBe('Mit Passkey anmelden')
    expect(translations.de!.passkeys.addPasskey).toBe(en.passkeys.addPasskey)
    expect(translations.fr!.passkeys.addPasskey).toBe(en.passkeys.addPasskey)
    expect((translations.fr as unknown as { general: unknown }).general).toEqual({ x: 'y' })
    expect(Object.keys(translations).sort()).toEqual(['de', 'en', 'fr'])
  })
})

describe('passkeysPlugin', () => {
  const host = (): Config =>
    ({
      collections: [{ slug: 'users', auth: true, fields: [] }],
      i18n: { translations: { en: { passkeys: { signInWithPasskey: 'Use a passkey' } } } },
      secret: 'x',
      serverURL: 'https://example.com',
    }) as unknown as Config

  it.each([true, false])(
    'adds the namespace when enabled is %s, keeping host overrides',
    (enabled) => {
      const translations = passkeysPlugin({ enabled })(host()).i18n?.translations as Record<
        string,
        { passkeys: Record<string, string> }
      >
      expect(translations.en!.passkeys.signInWithPasskey).toBe('Use a passkey')
      expect(translations.en!.passkeys.addPasskey).toBe(en.passkeys.addPasskey)
    },
  )
})

describe('English copy', () => {
  it('has the keys the admin UI needs', () => {
    expect(en.passkeys).toMatchObject({ enrolAdd: 'Add a passkey', retry: 'Try again' })
  })

  const strings = Object.entries(en.passkeys)

  it('gives every key that mentions a password a neutral Sso sibling', () => {
    const copy: Record<string, string> = en.passkeys
    const mentioning = Object.keys(copy).filter(
      (key) => !key.endsWith('Sso') && /password/i.test(copy[key]!),
    )
    // Only the password prompt itself may mention one without a sibling.
    const prompt = [
      'confirm',
      'confirmPasswordBody',
      'confirmPasswordTitle',
      'password',
      'wrongPassword',
    ]
    for (const key of mentioning.filter((k) => !prompt.some((p) => k === p))) {
      expect(SSO_KEYS, key).toContain(key)
    }
    for (const key of SSO_KEYS) {
      expect(copy[`${key}Sso`], key).toBeTypeOf('string')
      expect(copy[`${key}Sso`], key).not.toMatch(/password/i)
    }
  })

  it('uses UK spelling', () => {
    const us =
      /\b(color|behavior|center|organiz|authoriz|recogniz|customiz|canceled|favorite|analyz)/i
    expect(strings.filter(([, value]) => us.test(value))).toEqual([])
  })

  it('uses curly apostrophes and the ellipsis character consistently', () => {
    expect(strings.filter(([, value]) => value.includes("'") || value.includes('...'))).toEqual([])
  })

  it('names every interpolation it uses', () => {
    for (const [, value] of strings) {
      for (const match of value.matchAll(/\{\{(\w+)\}\}/g))
        expect(['count', 'date', 'name', 'rpID']).toContain(match[1])
    }
  })
})
