'use client'

/**
 * Fired on window when a passkey is added outside the Passkeys section (the enrolment prompt),
 * so an open account page reloads its list. The section's state is client-side, so
 * router.refresh() alone would not reload it.
 */
export const PASSKEYS_CHANGED_EVENT = 'payload-passkeys:changed'

export const announcePasskeysChanged = (): void => {
  window.dispatchEvent(new Event(PASSKEYS_CHANGED_EVENT))
}
