'use client'
import { Button, useAuth, useConfig } from '@payloadcms/ui'
import {
  browserSupportsWebAuthn,
  sendSignal,
  startAuthentication,
  startRegistration,
} from '@simplewebauthn/browser'
import React, { useEffect, useMemo, useState } from 'react'

import '../passkeys.css'
import { ENDPOINTS } from '../../shared/constants.js'
import { safeAdminRedirect } from '../../shared/redirect.js'
import { createApi } from '../shared/api.js'
import { signInFlow } from '../shared/flows.js'
import { useRouter, useSearchParams } from '../shared/navigation.js'
import type { Reauthentication } from '../shared/reauthentication.js'
import { usePasskeysT } from '../shared/usePasskeysT.js'

type State = 'checking' | 'hidden' | 'ready' | 'unavailable' | 'working'

/** Under the login form: "or", then "Sign in with a passkey" (design 4.2). */
export const SignInWithPasskey: React.FC<{
  collectionSlug: string
  reauthentication?: Reauthentication
}> = ({ collectionSlug, reauthentication = 'password' }) => {
  const { config } = useConfig()
  const { setUser } = useAuth()
  const router = useRouter()
  const searchParams = useSearchParams()
  const { t } = usePasskeysT(reauthentication)
  const api = useMemo(
    () => createApi(config.routes.api, collectionSlug),
    [config.routes.api, collectionSlug],
  )
  const [state, setState] = useState<State>('checking')
  const [error, setError] = useState<null | string>(null)

  useEffect(() => {
    let live = true
    const check = async () => {
      // Unsupported browser: no button and no note; the password form is all there is.
      if (!browserSupportsWebAuthn()) return 'hidden'
      const reply = await api(ENDPOINTS.status)
      // A failed status check hides the button rather than claiming the host is wrong.
      if (!reply.ok) return 'hidden'
      return reply.data.available ? 'ready' : 'unavailable'
    }
    void check().then((next) => {
      if (live) setState(next)
    })
    return () => {
      live = false
    }
  }, [api])

  if (state === 'checking' || state === 'hidden') return null
  if (state === 'unavailable') {
    return (
      <div className="passkeys-sign-in">
        <p className="passkeys-note">{t('signInUnavailableHere')}</p>
      </div>
    )
  }

  const working = state === 'working'
  const onClick = async () => {
    setError(null)
    setState('working')
    const result = await signInFlow({
      api,
      browser: { sendSignal, startAuthentication, startRegistration },
    })
    if (!result.ok) {
      setError(t(result.message))
      setState('ready')
      return
    }
    // Same as Payload's LoginForm: hand the body to the auth provider, then navigate. The state
    // stays 'working' so the button can't be pressed twice while the admin loads.
    setUser(result.body as never)
    router.push(safeAdminRedirect(searchParams?.get('redirect'), config.routes.admin))
  }

  return (
    <div className="passkeys-sign-in">
      <div aria-hidden="true" className="passkeys-sign-in__or">
        <span>{t('or')}</span>
      </div>
      <Button
        buttonStyle="secondary"
        className="passkeys-sign-in__button"
        disabled={working}
        extraButtonProps={{ 'aria-busy': working }}
        margin={false}
        onClick={() => void onClick()}
        size="large"
        type="button"
      >
        {t('signInWithPasskey')}
      </Button>
      <p aria-live="polite" className="passkeys-status">
        {working ? t('signingIn') : ''}
      </p>
      {error ? (
        <p className="passkeys-error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  )
}
