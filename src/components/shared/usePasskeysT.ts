'use client'
import { useTranslation } from '@payloadcms/ui'
import { useCallback } from 'react'

import type { PasskeysTranslationKey } from '../../translations/en.js'
import type { Reauthentication } from './reauthentication.js'

import { keyForMode } from '../../shared/ssoKeys.js'

/**
 * `reauthentication` is the plugin's option. In 'sign-in-again' mode (SSO sites) a key with an
 * `Sso` sibling reads the sibling, so no text mentions a password the admin doesn't have. A host
 * that overrides only the base key still wins: withPasskeysTranslations copies it to the sibling.
 */
export const usePasskeysT = (reauthentication: Reauthentication = 'password') => {
  const { i18n, t } = useTranslation()
  const translate = t as unknown as (key: string, vars?: Record<string, unknown>) => string
  const passkeysT = useCallback(
    (key: PasskeysTranslationKey, vars?: Record<string, number | string>) =>
      translate(`passkeys:${keyForMode(key, reauthentication)}`, vars),
    [reauthentication, translate],
  )
  return { language: i18n.language, t: passkeysT }
}
