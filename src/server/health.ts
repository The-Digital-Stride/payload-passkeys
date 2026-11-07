/**
 * Why passkey ceremonies are off for a Payload instance, if they are. Set at boot when the
 * protection single use rests on is missing (a MongoDB unique index), so the plugin fails closed
 * for sign-in and registration instead of running without it. Password sign-in is untouched.
 *
 * The cause can be passing: on a first deploy, a burst of serverless cold starts building the
 * indexes at once met a dropped Atlas connection, and those instances stayed off until restarted.
 * So the check runs again from a request (`refreshCeremoniesDisabled`), one run at a time and at
 * most once per RECHECK_INTERVAL_MS, and the ceremonies come back once it passes.
 */
export type CeremoniesDisabledReason = 'indexes'

/** Runs the boot check again; true when the protection is in place now. */
export type HealthRecheck = () => Promise<boolean>

type DisabledState = {
  nextAttemptAt: number
  reason: CeremoniesDisabledReason
  recheck?: HealthRecheck
  running?: Promise<void>
}

/** At most one re-check per instance in this window, so a persistent cause isn't hammered. */
export const RECHECK_INTERVAL_MS = 30_000
/** How long a request waits for a re-check before answering with the state it has. */
export const RECHECK_WAIT_MS = 3_000

const disabled = new WeakMap<object, DisabledState>()

export const setCeremoniesDisabled = (
  payload: object,
  reason: CeremoniesDisabledReason | null,
  recheck?: HealthRecheck,
): void => {
  // The first request after a failed boot may re-check straight away.
  if (reason) disabled.set(payload, { nextAttemptAt: 0, reason, recheck })
  else disabled.delete(payload)
}

export const ceremoniesDisabledReason = (payload: object): CeremoniesDisabledReason | null =>
  disabled.get(payload)?.reason ?? null

const waitAtMost = (ms: number, promise: Promise<void>): Promise<void> => {
  let timer: ReturnType<typeof setTimeout> | undefined
  const timeout = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, ms)
    timer.unref?.()
  })
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer))
}

/**
 * The reason ceremonies are off, after re-running the check when one is due. The request waits
 * up to RECHECK_WAIT_MS for it; a slower check carries on in the background for later requests.
 * Never turns ceremonies on without the check passing.
 */
export const refreshCeremoniesDisabled = async (
  payload: object,
): Promise<CeremoniesDisabledReason | null> => {
  const state = disabled.get(payload)
  if (!state) return null
  if (state.recheck && !state.running && Date.now() >= state.nextAttemptAt) {
    const recheck = state.recheck
    state.running = recheck()
      .catch(() => false)
      .then((healthy) => {
        // Only clear the state this run belongs to: a later boot may have replaced it.
        if (healthy && disabled.get(payload) === state) disabled.delete(payload)
      })
      .finally(() => {
        state.running = undefined
        state.nextAttemptAt = Date.now() + RECHECK_INTERVAL_MS
      })
  }
  if (state.running) await waitAtMost(RECHECK_WAIT_MS, state.running)
  return ceremoniesDisabledReason(payload)
}
