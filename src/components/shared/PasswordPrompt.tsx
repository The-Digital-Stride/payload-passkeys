'use client'
import { Button, Modal, useModal } from '@payloadcms/ui'
import React, { useCallback, useEffect, useId, useRef, useState } from 'react'

import type { PasskeysTranslationKey } from '../../translations/en.js'

import { usePasskeysT } from './usePasskeysT.js'

/**
 * The password re-check for the fresh-session rule (design 4.1), as one modal shared by the
 * manager and the enrolment prompt.
 *
 * `ask(error?)` opens the modal (or keeps it open, showing `error`) and resolves with the
 * password, or null when dismissed. The modal stays open while the password is checked, so a
 * wrong password doesn't make it flicker; call `close()` once the flow has moved on.
 */
export const usePasswordPrompt = (slug: string) => {
  const { closeModal, isModalOpen, openModal } = useModal()
  const { t } = usePasskeysT()
  const id = useId()
  const resolver = useRef<((value: null | string) => void) | null>(null)
  const [error, setError] = useState<PasskeysTranslationKey | undefined>()
  const [password, setPassword] = useState('')
  const [checking, setChecking] = useState(false)
  const open = isModalOpen(slug)

  const settle = useCallback((value: null | string) => {
    const resolve = resolver.current
    resolver.current = null
    resolve?.(value)
  }, [])

  const ask = useCallback(
    (nextError?: PasskeysTranslationKey) =>
      new Promise<null | string>((resolve) => {
        resolver.current = resolve
        setError(nextError)
        setPassword('')
        setChecking(false)
        openModal(slug)
      }),
    [openModal, slug],
  )

  const close = useCallback(() => {
    setChecking(false)
    closeModal(slug)
    settle(null)
  }, [closeModal, settle, slug])

  // The modal provider closes the latest modal on Esc (and on a click outside), without telling
  // us: faceless-ui's Modal has no working onClose. A close we didn't ask for means "dismissed".
  useEffect(() => {
    if (!open) settle(null)
  }, [open, settle])

  const element = (
    // faceless-ui names the dialog by its slug unless told otherwise: name it by its heading.
    <Modal
      aria-describedby={`${id}-body`}
      aria-labelledby={`${id}-title`}
      className="passkeys-modal"
      closeOnBlur={false}
      slug={slug}
    >
      <div className="passkeys-modal__wrapper">
        <form
          className="passkeys-modal__body"
          onSubmit={(event) => {
            event.preventDefault()
            // React events bubble through portals: without this, the document form this modal is
            // rendered from (the account page) would submit too.
            event.stopPropagation()
            if (!password || checking) return
            setChecking(true)
            settle(password)
          }}
        >
          <h2 id={`${id}-title`}>{t('confirmPasswordTitle')}</h2>
          <p id={`${id}-body`}>{t('confirmPasswordBody')}</p>
          <div className="field-type text passkeys-field">
            <label className="field-label" htmlFor={`${id}-password`}>
              {t('password')}
            </label>
            <div className="field-type__wrap">
              <input
                aria-describedby={error ? `${id}-error` : undefined}
                aria-invalid={error ? true : undefined}
                autoComplete="current-password"
                // The modal was opened by pressing a button, so focus moving here is expected.

                autoFocus
                id={`${id}-password`}
                onChange={(event) => setPassword(event.target.value)}
                required
                type="password"
                value={password}
              />
            </div>
          </div>
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
              disabled={checking}
              extraButtonProps={{ 'aria-busy': checking }}
              margin={false}
              type="submit"
            >
              {t('confirm')}
            </Button>
          </div>
        </form>
      </div>
    </Modal>
  )

  return { ask, close, element }
}
