'use client'
import { Button, toast, useAuth, useConfig } from '@payloadcms/ui'
import {
  browserSupportsWebAuthn,
  sendSignal,
  startAuthentication,
  startRegistration,
} from '@simplewebauthn/browser'
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
} from 'react'

import type { PasskeysTranslationKey } from '../../translations/en.js'
import type { PublicPasskey } from '../../types.js'

import '../passkeys.css'
import { ENDPOINTS } from '../../shared/constants.js'
import type { ApiReply } from '../shared/api.js'

import { createApi } from '../shared/api.js'
import { PASSKEYS_CHANGED_EVENT } from '../shared/events.js'
import { registerFlow, syncAcceptedCredentials } from '../shared/flows.js'
import { usePasswordPrompt } from '../shared/PasswordPrompt.js'
import { usePasskeysT } from '../shared/usePasskeysT.js'
import { PasskeyRow } from './PasskeyRow.js'

export type StatusData = {
  available: boolean
  passkeys: PublicPasskey[]
  reason?: string
  rpID?: string
  signalUserId?: null | string
}

type Load = { data: StatusData; kind: 'loaded' } | { kind: 'failed' } | { kind: 'loading' }

const browser = { sendSignal, startAuthentication, startRegistration }
const noSubscription = () => () => {}

/** UK house style reads "6 Nov 2026"; other languages use their own order. */
const dateLocale = (language: string) => (language === 'en' ? 'en-GB' : language)

/** The Passkeys section on the signed-in user's own account page (design 4.3). */
export const PasskeysManager: React.FC<{ collectionSlug: string }> = ({ collectionSlug }) => {
  const { config } = useConfig()
  const { setUser } = useAuth()
  const { language, t } = usePasskeysT()
  const api = useMemo(
    () => createApi(config.routes.api, collectionSlug),
    [config.routes.api, collectionSlug],
  )
  const prompt = usePasswordPrompt('passkeys-password')
  const [load, setLoad] = useState<Load>({ kind: 'loading' })
  // Assumed true on the server and during hydration, then read from the browser.
  const supported = useSyncExternalStore(noSubscription, browserSupportsWebAuthn, () => true)
  const [adding, setAdding] = useState(false)
  const [addError, setAddError] = useState<null | PasskeysTranslationKey>(null)

  const formatDate = useMemo(() => {
    const format = new Intl.DateTimeFormat(dateLocale(language), { dateStyle: 'medium' })
    return (iso: string) => {
      const date = new Date(iso)
      return Number.isNaN(date.getTime()) ? '' : format.format(date)
    }
  }, [language])

  /** Applies a status reply: the section's one read (list, RP ID and signal user ID). */
  const apply = useCallback((reply: ApiReply) => {
    if (!reply.ok || !Array.isArray(reply.data.passkeys)) {
      setLoad({ kind: 'failed' })
      return
    }
    const data = reply.data as unknown as StatusData
    setLoad({ data, kind: 'loaded' })
    if (data.rpID) {
      void syncAcceptedCredentials(browser, {
        credentialIds: data.passkeys.map((passkey) => passkey.credentialId),
        rpID: data.rpID,
        userId: data.signalUserId ?? null,
      })
    }
  }, [])

  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    const load = () => {
      void api(ENDPOINTS.status).then((reply) => {
        if (mounted.current) apply(reply)
      })
    }
    load()
    // The enrolment prompt can add a passkey while this page is open.
    window.addEventListener(PASSKEYS_CHANGED_EVENT, load)
    return () => {
      mounted.current = false
      window.removeEventListener(PASSKEYS_CHANGED_EVENT, load)
    }
  }, [api, apply])

  const reload = async () => {
    const reply = await api(ENDPOINTS.status)
    if (mounted.current) apply(reply)
  }

  const retry = () => {
    setLoad({ kind: 'loading' })
    void reload()
  }

  const add = async () => {
    setAddError(null)
    setAdding(true)
    try {
      const result = await registerFlow({
        api,
        askPassword: prompt.ask,
        browser,
        onReauthenticated: (body) => {
          prompt.close()
          setUser(body as never)
        },
      })
      if (result.ok) {
        toast.success(t('added'))
        await reload()
      } else if (result.message !== 'addCancelled') {
        setAddError(result.message)
      }
    } finally {
      prompt.close()
      setAdding(false)
    }
  }

  const heading = <h3 className="passkeys-manager__title">{t('sectionTitle')}</h3>

  if (load.kind === 'loading') {
    return (
      <section aria-busy="true" className="passkeys-manager">
        {heading}
        <div className="passkeys-skeleton" />
      </section>
    )
  }

  if (load.kind === 'failed') {
    return (
      <section className="passkeys-manager">
        {heading}
        <p className="passkeys-error" role="alert">
          {t('genericError')}
        </p>
        <div>
          <Button buttonStyle="secondary" margin={false} onClick={retry} size="small">
            {t('retry')}
          </Button>
        </div>
      </section>
    )
  }

  const { available, passkeys, reason, rpID } = load.data
  const canAdd = supported && available

  return (
    <section className="passkeys-manager">
      {heading}
      <p className="passkeys-manager__description">{t('sectionDescription')}</p>
      {passkeys.length ? (
        <ul className="passkeys-list">
          {passkeys.map((passkey) => (
            <PasskeyRow
              api={api}
              currentRpID={rpID}
              formatDate={formatDate}
              isOnly={passkeys.length === 1}
              key={String(passkey.id)}
              onChanged={() => void reload()}
              passkey={passkey}
            />
          ))}
        </ul>
      ) : (
        <p className="passkeys-note">{t('none')}</p>
      )}
      {!supported ? <p className="passkeys-note">{t('unsupportedBrowser')}</p> : null}
      {supported && !available && reason === 'indexes' ? (
        // Boot turned passkeys off (src/server/health.ts); the server log says why.
        <p className="passkeys-note">{t('genericError')}</p>
      ) : null}
      {supported && !available && reason !== 'indexes' && rpID ? (
        <p className="passkeys-note">{t('worksOnlyOn', { rpID })}</p>
      ) : null}
      {canAdd ? (
        <div className="passkeys-manager__add">
          <Button
            buttonStyle="secondary"
            disabled={adding}
            extraButtonProps={{ 'aria-busy': adding }}
            margin={false}
            onClick={() => void add()}
          >
            {t('addPasskey')}
          </Button>
          <p aria-live="polite" className="passkeys-status">
            {adding ? t('adding') : ''}
          </p>
        </div>
      ) : null}
      {addError ? (
        <p className="passkeys-error" role="alert">
          {t(addError)}
        </p>
      ) : null}
      {prompt.element}
    </section>
  )
}
