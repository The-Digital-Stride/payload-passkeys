'use client'
import { useAuth, useConfig } from '@payloadcms/ui'
import { platformAuthenticatorIsAvailable } from '@simplewebauthn/browser'
import React, { useEffect, useMemo, useRef, useState } from 'react'

import '../passkeys.css'
import { ENDPOINTS } from '../../shared/constants.js'
import { createApi } from '../shared/api.js'
import { rememberChoice, shouldOfferEnrolment } from '../shared/enrolmentStorage.js'
import type { Reauthentication } from '../shared/reauthentication.js'
import { EnrolmentPrompt } from './EnrolmentPrompt.js'

type Props = {
  children: React.ReactNode
  collections: string[]
  enrolmentPrompt: boolean
  reauthentication?: Reauthentication
}

type Offer = { collection: string; userId: number | string }

/** Browser storage, or null where reading it throws (storage disabled). */
const storage = (kind: 'localStorage' | 'sessionStorage'): null | Storage => {
  try {
    return window[kind]
  } catch {
    return null
  }
}

/**
 * Wraps the admin. Offers a passkey after a password sign-in (design 4.4); in phase 2 it also
 * hosts the lock screen.
 */
export const PasskeysProvider: React.FC<Props> = ({
  children,
  collections,
  enrolmentPrompt,
  reauthentication = 'password',
}) => {
  const { user } = useAuth()
  const { config } = useConfig()
  const [offer, setOffer] = useState<null | Offer>(null)
  // One decision per user per mount: shouldOfferEnrolment spends the browser session's one
  // chance, so a re-run of the effect (React Strict Mode, a new `user` object after a token
  // refresh) must not ask it again.
  const decided = useRef(new Map<string, boolean>())

  const collection = typeof user?.collection === 'string' ? user.collection : undefined
  const userId = user?.id as number | string | undefined
  const api = useMemo(
    () => (collection ? createApi(config.routes.api, collection) : null),
    [collection, config.routes.api],
  )

  useEffect(() => {
    // Checks 1 to 3 are local, so an ordinary page view makes no request.
    if (!enrolmentPrompt || !api || !collection || userId === undefined) return
    if (!collections.includes(collection)) return
    const key = `${collection}:${String(userId)}`
    let wanted = decided.current.get(key)
    if (wanted === undefined) {
      const local = storage('localStorage')
      const session = storage('sessionStorage')
      wanted =
        local !== null &&
        session !== null &&
        shouldOfferEnrolment({ collection, local, now: new Date(), session, userId })
      decided.current.set(key, wanted)
    }
    if (!wanted) return

    let live = true
    const check = async () => {
      if (!(await platformAuthenticatorIsAvailable().catch(() => false))) return false
      const reply = await api(ENDPOINTS.status)
      const passkeys = reply.data.passkeys
      return (
        reply.ok && reply.data.available === true && Array.isArray(passkeys) && !passkeys.length
      )
    }
    void check().then((show) => {
      if (live && show) setOffer({ collection, userId })
    })
    return () => {
      live = false
    }
  }, [api, collection, collections, enrolmentPrompt, userId])

  const current =
    offer && api && offer.collection === collection && offer.userId === userId ? offer : null

  const done = (choice?: 'never' | 'not-now') => {
    const local = storage('localStorage')
    if (current) {
      // Not again in this mount, whatever the storage allowed.
      decided.current.set(`${current.collection}:${String(current.userId)}`, false)
      if (choice && local) {
        rememberChoice(local, current.collection, current.userId, choice, new Date())
      }
    }
    setOffer(null)
  }

  return (
    <>
      {children}
      {current && api ? (
        <EnrolmentPrompt
          api={api}
          collectionSlug={current.collection}
          onDone={done}
          reauthentication={reauthentication}
        />
      ) : null}
    </>
  )
}
