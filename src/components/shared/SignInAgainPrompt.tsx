'use client'
import { Button, Modal, useConfig, useModal } from '@payloadcms/ui'
import React, { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react'

import type { PasskeysTranslationKey } from '../../translations/en.js'

import { createApi } from './api.js'
import { sessionMayRemain, signInAgainUrl } from './signInAgain.js'
import { usePasskeysT } from './usePasskeysT.js'

/**
 * The dialog for SSO sites (`reauthentication: 'sign-in-again'`), where there is no password to
 * re-check: it ends the session and sends the admin to the login page, then back here.
 *
 * `ask()` opens the modal and resolves true when "Sign in again" was used (the page is leaving),
 * false when dismissed. Same shape and accessibility as usePasswordPrompt.
 */
export const useSignInAgainPrompt = (slug: string, collectionSlug: string) => {
  const { config } = useConfig()
  const { closeModal, isModalOpen, openModal } = useModal()
  const { t } = usePasskeysT()
  const id = useId()
  const resolver = useRef<((value: boolean) => void) | null>(null)
  const [error, setError] = useState<PasskeysTranslationKey | undefined>()
  const [working, setWorking] = useState(false)
  const open = isModalOpen(slug)
  // Set once the session has ended and the page is on its way to the login route: from then on
  // the dialog stays exactly as it is until the page unloads.
  const leaving = useRef(false)
  const api = useMemo(
    () => createApi(config.routes.api, collectionSlug),
    [config.routes.api, collectionSlug],
  )

  const settle = useCallback((value: boolean) => {
    const resolve = resolver.current
    resolver.current = null
    resolve?.(value)
  }, [])

  const ask = useCallback(
    () =>
      new Promise<boolean>((resolve) => {
        resolver.current = resolve
        leaving.current = false
        setError(undefined)
        setWorking(false)
        openModal(slug)
      }),
    [openModal, slug],
  )

  const close = useCallback(() => {
    if (leaving.current) return
    setWorking(false)
    closeModal(slug)
    settle(false)
  }, [closeModal, settle, slug])

  // Esc and a click outside close the modal without telling us: that means "dismissed".
  useEffect(() => {
    if (!open && !leaving.current) settle(false)
  }, [open, settle])

  const signInAgain = async () => {
    if (working) return
    setError(undefined)
    setWorking(true)
    // Payload's login page sends a signed-in user straight back to the admin, so the session has
    // to end first. If it can't be ended, stay here rather than bounce.
    const reply = await api('/logout')
    if (!reply.ok && sessionMayRemain(reply.status)) {
      setWorking(false)
      setError('genericError')
      return
    }
    leaving.current = true
    settle(true)
    window.location.assign(
      signInAgainUrl({
        adminRoute: config.routes.admin,
        current: `${window.location.pathname}${window.location.search}`,
        loginRoute: config.admin?.routes?.login,
      }),
    )
  }

  const element = (
    <Modal
      aria-describedby={`${id}-body`}
      aria-labelledby={`${id}-title`}
      className="passkeys-modal"
      closeOnBlur={false}
      slug={slug}
    >
      <div className="passkeys-modal__wrapper">
        <div className="passkeys-modal__body">
          <h2 id={`${id}-title`}>{t('signInAgainTitle')}</h2>
          <p id={`${id}-body`}>{t('signInAgainBody')}</p>
          {error ? (
            <p className="passkeys-error" id={`${id}-error`} role="alert">
              {t(error)}
            </p>
          ) : null}
          <div className="passkeys-modal__actions">
            <Button buttonStyle="secondary" margin={false} onClick={close} type="button">
              {t('cancel')}
            </Button>
            <Button
              // The modal was opened by pressing a button, so focus moving here is expected.
              disabled={working}
              extraButtonProps={{ 'aria-busy': working, autoFocus: true }}
              margin={false}
              onClick={() => void signInAgain()}
              type="button"
            >
              {t('signInAgain')}
            </Button>
          </div>
        </div>
      </div>
    </Modal>
  )

  return { ask, close, element }
}
