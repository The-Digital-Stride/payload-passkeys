'use client'
import { Button, toast, useAuth } from '@payloadcms/ui'
import { sendSignal, startAuthentication, startRegistration } from '@simplewebauthn/browser'
import React, { useId, useState } from 'react'

import type { PasskeysTranslationKey } from '../../translations/en.js'
import type { Api } from '../shared/api.js'

import { announcePasskeysChanged } from '../shared/events.js'
import { registerFlow } from '../shared/flows.js'
import { usePasswordPrompt } from '../shared/PasswordPrompt.js'
import { usePasskeysT } from '../shared/usePasskeysT.js'

const browser = { sendSignal, startAuthentication, startRegistration }

type Props = {
  api: Api
  /** Hides the card; `choice` is what to remember, if anything. */
  onDone: (choice?: 'never' | 'not-now') => void
}

/**
 * "Sign in faster with a passkey" (design 4.4): a non-modal card in the corner. It never takes
 * focus; Esc inside it means "Not now".
 */
export const EnrolmentPrompt: React.FC<Props> = ({ api, onDone }) => {
  const { setUser } = useAuth()
  const { t } = usePasskeysT()
  const id = useId()
  const prompt = usePasswordPrompt('passkeys-enrol-password')
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState<null | PasskeysTranslationKey>(null)

  const add = async () => {
    setError(null)
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
        announcePasskeysChanged()
        onDone()
      } else if (result.message !== 'addCancelled') {
        setError(result.message)
      }
    } finally {
      prompt.close()
      setAdding(false)
    }
  }

  return (
    <>
      <div
        aria-describedby={`${id}-body`}
        aria-labelledby={`${id}-title`}
        className="passkeys-enrol"
        onKeyDown={(event) => {
          // Only for keys pressed inside the card itself: React also bubbles events from the
          // password modal's portal up to here.
          if (
            event.key === 'Escape' &&
            !adding &&
            event.currentTarget.contains(event.target as Node)
          ) {
            event.preventDefault()
            onDone('not-now')
          }
        }}
        role="dialog"
      >
        <h2 className="passkeys-enrol__title" id={`${id}-title`}>
          {t('enrolTitle')}
        </h2>
        <p className="passkeys-enrol__body" id={`${id}-body`}>
          {t('enrolBody')}
        </p>
        {error ? (
          <p className="passkeys-error" role="alert">
            {t(error)}
          </p>
        ) : null}
        <p aria-live="polite" className="passkeys-status">
          {adding ? t('adding') : ''}
        </p>
        <div className="passkeys-enrol__actions">
          <Button
            disabled={adding}
            extraButtonProps={{ 'aria-busy': adding }}
            margin={false}
            onClick={() => void add()}
            size="small"
          >
            {t('enrolAdd')}
          </Button>
          <Button
            buttonStyle="secondary"
            disabled={adding}
            margin={false}
            onClick={() => onDone('not-now')}
            size="small"
          >
            {t('notNow')}
          </Button>
          <Button
            buttonStyle="subtle"
            disabled={adding}
            margin={false}
            onClick={() => onDone('never')}
            size="small"
          >
            {t('dontAskAgain')}
          </Button>
        </div>
      </div>
      {prompt.element}
    </>
  )
}
