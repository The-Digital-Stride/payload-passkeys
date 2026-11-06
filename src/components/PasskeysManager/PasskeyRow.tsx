'use client'
import { Button, CheckboxInput, ConfirmationModal, toast, useModal } from '@payloadcms/ui'
import React, { useId, useState } from 'react'

import type { PublicPasskey } from '../../types.js'
import type { Api } from '../shared/api.js'

import { providerName } from '../../shared/aaguid.js'
import { ENDPOINTS, MAX_PASSKEY_NAME } from '../../shared/constants.js'
import { usePasskeysT } from '../shared/usePasskeysT.js'

const DAY_MS = 24 * 60 * 60 * 1000

/** Review M6: removing a passkey used in the last day also ends the sessions it may have made. */
export const recentlyUsed = (lastUsedAt: null | string, now = Date.now()): boolean => {
  if (!lastUsedAt) return false
  const used = Date.parse(lastUsedAt)
  return Number.isFinite(used) && now - used < DAY_MS
}

const KeyIcon = () => (
  <svg
    aria-hidden="true"
    className="passkeys-row__icon"
    fill="none"
    focusable="false"
    height="20"
    stroke="currentColor"
    strokeLinecap="round"
    strokeLinejoin="round"
    strokeWidth="1.5"
    viewBox="0 0 24 24"
    width="20"
  >
    <circle cx="8" cy="15" r="4" />
    <path d="M10.85 12.15 19 4" />
    <path d="m18 5 2 2" />
    <path d="m15 8 2 2" />
  </svg>
)

type Props = {
  api: Api
  /** The plugin's current RP ID, to flag passkeys made for another one (design §5). */
  currentRpID?: string
  formatDate: (iso: string) => string
  isOnly: boolean
  onChanged: () => void
  passkey: PublicPasskey
}

export const PasskeyRow: React.FC<Props> = ({
  api,
  currentRpID,
  formatDate,
  isOnly,
  onChanged,
  passkey,
}) => {
  const { t } = usePasskeysT()
  const { openModal } = useModal()
  const id = useId()
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(passkey.name)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<null | string>(null)
  const [signOutOthers, setSignOutOthers] = useState(false)
  const removeSlug = `passkeys-remove-${String(passkey.id)}`

  const provider = providerName(passkey.aaguid)
  const showProvider = provider !== null && provider !== passkey.name

  const startRename = () => {
    setDraft(passkey.name)
    setError(null)
    setEditing(true)
  }

  const cancelRename = () => {
    setEditing(false)
    setError(null)
  }

  const saveRename = async () => {
    const name = draft.trim()
    if (!name) return setError(t('nameRequired'))
    if (name === passkey.name) return cancelRename()
    setSaving(true)
    setError(null)
    const reply = await api(ENDPOINTS.rename, { id: passkey.id, name })
    setSaving(false)
    if (!reply.ok) return setError(t('genericError'))
    setEditing(false)
    toast.success(t('renamed'))
    onChanged()
  }

  const askRemove = () => {
    setSignOutOthers(recentlyUsed(passkey.lastUsedAt))
    setError(null)
    openModal(removeSlug)
  }

  const remove = async () => {
    const reply = await api(ENDPOINTS.delete, {
      id: passkey.id,
      signOutOtherSessions: signOutOthers,
    })
    if (!reply.ok) {
      toast.error(t('removeFailed'))
      return
    }
    toast.success(t('removed'))
    onChanged()
  }

  return (
    <li className="passkeys-row">
      <KeyIcon />
      <div className="passkeys-row__main">
        {editing ? (
          <div className="field-type text passkeys-field passkeys-row__rename">
            <label className="field-label" htmlFor={`${id}-name`}>
              {t('name')}
            </label>
            <div className="field-type__wrap">
              <input
                aria-describedby={error ? `${id}-error` : undefined}
                aria-invalid={error ? true : undefined}
                // Pressing Rename asks for this input, so moving focus to it is expected.

                autoFocus
                id={`${id}-name`}
                maxLength={MAX_PASSKEY_NAME}
                onChange={(event) => setDraft(event.target.value)}
                onKeyDown={(event) => {
                  // The account page is one big form: Enter here must not save the document.
                  if (event.key === 'Enter') {
                    event.preventDefault()
                    void saveRename()
                  } else if (event.key === 'Escape') {
                    event.preventDefault()
                    event.stopPropagation()
                    cancelRename()
                  }
                }}
                type="text"
                value={draft}
              />
            </div>
          </div>
        ) : (
          <p className="passkeys-row__name">
            <span>{passkey.name}</span>
            {showProvider ? <span className="passkeys-row__provider">{provider}</span> : null}
            <span className="passkeys-pill">
              {passkey.backedUp ? t('synced') : t('thisDeviceOnly')}
            </span>
          </p>
        )}
        <p className="passkeys-row__meta">
          <span>{t('created', { date: formatDate(passkey.createdAt) })}</span>
          <span>
            {passkey.lastUsedAt
              ? t('lastUsed', { date: formatDate(passkey.lastUsedAt) })
              : t('neverUsed')}
          </span>
          {currentRpID && passkey.rpID && passkey.rpID !== currentRpID ? (
            <span>{t('madeFor', { rpID: passkey.rpID })}</span>
          ) : null}
        </p>
        {error ? (
          <p className="passkeys-error" id={`${id}-error`} role="alert">
            {error}
          </p>
        ) : null}
      </div>
      <div className="passkeys-row__actions">
        {editing ? (
          <>
            <Button
              buttonStyle="secondary"
              disabled={saving}
              extraButtonProps={{ 'aria-busy': saving }}
              margin={false}
              onClick={() => void saveRename()}
              size="small"
            >
              {t('save')}
            </Button>
            <Button buttonStyle="secondary" margin={false} onClick={cancelRename} size="small">
              {t('cancel')}
            </Button>
          </>
        ) : (
          <>
            <Button
              aria-label={`${t('rename')}: ${passkey.name}`}
              buttonStyle="secondary"
              margin={false}
              onClick={startRename}
              size="small"
            >
              {t('rename')}
            </Button>
            <Button
              aria-label={`${t('remove')}: ${passkey.name}`}
              buttonStyle="secondary"
              margin={false}
              onClick={askRemove}
              size="small"
            >
              {t('remove')}
            </Button>
          </>
        )}
      </div>
      <ConfirmationModal
        body={
          <div className="passkeys-remove">
            <p>{isOnly ? t('removeLast') : t('removeKeepsOthers')}</p>
            <CheckboxInput
              checked={signOutOthers}
              id={`${id}-sign-out`}
              label={t('alsoSignOut')}
              onToggle={(event) => setSignOutOthers(event.target.checked)}
            />
            <p className="passkeys-note">{t('alsoSignOutHint')}</p>
          </div>
        }
        cancelLabel={t('cancel')}
        confirmLabel={t('remove')}
        heading={t('removeTitle', { name: passkey.name })}
        modalSlug={removeSlug}
        onConfirm={remove}
      />
    </li>
  )
}
