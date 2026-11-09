import type { Config } from 'payload'

import { SSO_KEYS } from '../shared/ssoKeys.js'
import { en } from './en.js'

type Translations = Record<string, Record<string, unknown>>

export const withPasskeysTranslations = (i18n: Config['i18n']): Config['i18n'] => {
  const existing = (i18n?.translations ?? {}) as Translations
  const languages = new Set([
    'en',
    ...Object.keys(i18n?.supportedLanguages ?? {}),
    ...Object.keys(existing),
  ])
  const translations: Translations = { ...existing }
  for (const language of languages) {
    const current = translations[language] ?? {}
    const overrides = (current.passkeys ?? {}) as Record<string, string>
    // A host that rewrote a base key but not its `…Sso` sibling keeps its text on SSO sites too.
    const siblings: Record<string, string> = {}
    for (const key of SSO_KEYS) {
      if (key in overrides && !(`${key}Sso` in overrides))
        siblings[`${key}Sso`] = overrides[key] as string
    }
    translations[language] = {
      ...current,
      passkeys: { ...en.passkeys, ...siblings, ...overrides },
    }
  }
  return { ...i18n, translations: translations as NonNullable<Config['i18n']>['translations'] }
}
