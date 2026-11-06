'use client'
import { useTranslation } from '@payloadcms/ui'

import type { PasskeysTranslationKey } from '../../translations/en.js'

export const usePasskeysT = () => {
  const { i18n, t } = useTranslation()
  const translate = t as unknown as (key: string, vars?: Record<string, unknown>) => string
  return {
    language: i18n.language,
    t: (key: PasskeysTranslationKey, vars?: Record<string, number | string>) =>
      translate(`passkeys:${key}`, vars),
  }
}
