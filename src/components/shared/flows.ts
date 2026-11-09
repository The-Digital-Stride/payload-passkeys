'use client'
import type { sendSignal, startAuthentication, startRegistration } from '@simplewebauthn/browser'

import type { PasskeysTranslationKey } from '../../translations/en.js'
import type { Api } from './api.js'

import { ENDPOINTS } from '../../shared/constants.js'
import type { Reauthentication } from './reauthentication.js'

export type { Api } from './api.js'
export type Browser = {
  sendSignal: typeof sendSignal
  startAuthentication: typeof startAuthentication
  startRegistration: typeof startRegistration
}
type Fail = { message: PasskeysTranslationKey; ok: false }
const fail = (message: PasskeysTranslationKey): Fail => ({ message, ok: false })

const errorName = (error: unknown): string | undefined => {
  const e = error as { cause?: { name?: string }; name?: string } | null
  return e?.cause?.name ?? e?.name
}
const isCancel = (error: unknown): boolean =>
  ['AbortError', 'NotAllowedError'].includes(errorName(error) ?? '') ||
  (error as { code?: string } | null)?.code === 'ERROR_CEREMONY_ABORTED'

const throttled = (reply: { data: { error?: string }; status: number }): Fail | null =>
  reply.status === 429 ? fail(reply.data.error === 'busy' ? 'busy' : 'rateLimited') : null

export const signInFlow = async ({
  api,
  browser,
}: {
  api: Api
  browser: Browser
}): Promise<Fail | { body: Record<string, unknown>; ok: true }> => {
  const options = await api(ENDPOINTS.signInOptions)
  if (!options.ok) return throttled(options) ?? fail('signInFailed')
  const optionsJSON = options.data.options as Parameters<
    Browser['startAuthentication']
  >[0]['optionsJSON']
  let response
  try {
    response = await browser.startAuthentication({ optionsJSON })
  } catch (error) {
    return fail(isCancel(error) ? 'signInCancelled' : 'signInFailed')
  }
  const verify = await api(ENDPOINTS.signInVerify, { response })
  if (verify.ok) return { body: verify.data, ok: true }
  if (verify.data.unknownCredential && optionsJSON.rpId) {
    try {
      await browser.sendSignal({
        credentialID: response.id,
        rpID: optionsJSON.rpId,
        signalName: 'unknownCredential',
      })
    } catch {
      // Best effort.
    }
  }
  return throttled(verify) ?? fail('signInFailed')
}

export const registerFlow = async ({
  api,
  askPassword,
  askSignInAgain,
  browser,
  name,
  onReauthenticated,
  reauthentication = 'password',
}: {
  api: Api
  /** Shows the password prompt; resolves null when dismissed. The argument is an error to show. */
  askPassword: (error?: PasskeysTranslationKey) => Promise<null | string>
  /**
   * Shows the sign-in-again dialog (SSO sites, no password to ask for). Resolves false when
   * dismissed; true means the page is on its way to the login route.
   */
  askSignInAgain?: () => Promise<boolean>
  browser: Browser
  name?: string
  /** The session moved (review H1): hand the new body to useAuth().setUser. */
  onReauthenticated: (body: Record<string, unknown>) => void
  reauthentication?: Reauthentication
}): Promise<Fail | { ok: true; passkey: Record<string, unknown> }> => {
  let options = await api(ENDPOINTS.registerOptions)
  if (options.status === 403 && options.data.error === 'reauth_required') {
    if (reauthentication === 'sign-in-again') {
      // No password to check: the only way to a fresh session is another sign-in, so the page
      // leaves (or the user cancels). The reauth endpoint is never called.
      await askSignInAgain?.()
      return fail('addCancelled')
    }
    let error: PasskeysTranslationKey | undefined
    for (;;) {
      const password = await askPassword(error)
      if (password === null) return fail('addCancelled')
      const reauth = await api(ENDPOINTS.reauth, { password })
      if (reauth.ok) {
        onReauthenticated(reauth.data)
        break
      }
      const limited = throttled(reauth)
      if (limited) return limited
      // 401 is a wrong password (or a locked account, which must look the same). Anything else
      // (network, server error) won't be fixed by asking again.
      if (reauth.status !== 401) return fail('addFailed')
      error = 'wrongPassword'
    }
    options = await api(ENDPOINTS.registerOptions)
  }
  if (options.status === 409) return fail('tooMany')
  if (!options.ok) return throttled(options) ?? fail('addFailed')

  let response
  try {
    response = await browser.startRegistration({ optionsJSON: options.data.options as never })
  } catch (error) {
    if ((error as { code?: string } | null)?.code === 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED')
      return fail('alreadyOnDevice')
    return fail(isCancel(error) ? 'addCancelled' : 'addFailed')
  }
  const verify = await api(ENDPOINTS.registerVerify, { name, response })
  if (verify.ok) return { ok: true, passkey: verify.data.passkey as Record<string, unknown> }
  if (verify.status === 409) return fail('tooMany')
  return throttled(verify) ?? fail('addFailed')
}

/** Tells the password manager which passkeys still exist, so removed ones disappear. Best effort. */
export const syncAcceptedCredentials = async (
  browser: Pick<Browser, 'sendSignal'>,
  { credentialIds, rpID, userId }: { credentialIds: string[]; rpID: string; userId: null | string },
): Promise<void> => {
  if (!userId) return
  try {
    await browser.sendSignal({
      allAcceptedCredentialIDs: credentialIds,
      rpID,
      signalName: 'allAcceptedCredentials',
      userID: userId,
    })
  } catch {
    // Unsupported browser or no matching passkey: nothing to do.
  }
}

/**
 * What to tell the user after `delete`, and whether to reload the list. `sign_out_unconfirmed`
 * means the passkey is gone but other sessions weren't confirmed ended; `not_found` means it was
 * already gone. Either way the list on screen is out of date.
 */
export const removeOutcome = (reply: {
  data: { error?: string }
  ok: boolean
}): { message: PasskeysTranslationKey; ok: boolean; refresh: boolean } => {
  if (reply.ok) return { message: 'removed', ok: true, refresh: true }
  if (reply.data.error === 'sign_out_unconfirmed') {
    return { message: 'removedSignOutUnconfirmed', ok: false, refresh: true }
  }
  return { message: 'removeFailed', ok: false, refresh: reply.data.error === 'not_found' }
}
