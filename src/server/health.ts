/**
 * Why passkey ceremonies are off for a Payload instance, if they are. Set at boot when the
 * protection single use rests on is missing (a MongoDB unique index), so the plugin fails closed
 * for sign-in and registration instead of running without it. Password sign-in is untouched.
 */
export type CeremoniesDisabledReason = 'indexes'

const disabled = new WeakMap<object, CeremoniesDisabledReason>()

export const setCeremoniesDisabled = (
  payload: object,
  reason: CeremoniesDisabledReason | null,
): void => {
  if (reason) disabled.set(payload, reason)
  else disabled.delete(payload)
}

export const ceremoniesDisabledReason = (payload: object): CeremoniesDisabledReason | null =>
  disabled.get(payload) ?? null
