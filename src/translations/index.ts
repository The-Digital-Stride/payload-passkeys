import type { Config } from 'payload'

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
    translations[language] = {
      ...current,
      passkeys: { ...en.passkeys, ...(current.passkeys as Record<string, string> | undefined) },
    }
  }
  return { ...i18n, translations: translations as NonNullable<Config['i18n']>['translations'] }
}
