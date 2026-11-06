'use client'

type Store = Pick<Storage, 'getItem' | 'removeItem' | 'setItem'>
const NOT_NOW_MS = 30 * 24 * 60 * 60 * 1000
const key = (collection: string, userId: number | string) =>
  `payload-passkeys:enrol:${collection}:${String(userId)}`
const SESSION_KEY = 'payload-passkeys:enrol-seen'

/** 'never', 'not-now' (still within 30 days) or null. */
export const enrolmentChoice = (
  local: Store,
  collection: string,
  userId: number | string,
  now: Date,
): 'never' | 'not-now' | null => {
  const value = local.getItem(key(collection, userId))
  if (value === 'never') return 'never'
  if (value?.startsWith('not-now:')) {
    const until = Date.parse(value.slice('not-now:'.length))
    return Number.isFinite(until) && until > now.getTime() ? 'not-now' : null
  }
  return null
}

export const rememberChoice = (
  local: Store,
  collection: string,
  userId: number | string,
  choice: 'never' | 'not-now',
  now: Date,
): void => {
  try {
    local.setItem(
      key(collection, userId),
      choice === 'never'
        ? 'never'
        : `not-now:${new Date(now.getTime() + NOT_NOW_MS).toISOString()}`,
    )
  } catch {
    // Storage refused (private mode): the prompt simply comes back next session.
  }
}

/** True at most once per browser session, and never after "Don't ask again" or within "Not now". */
export const shouldOfferEnrolment = ({
  collection,
  local,
  now,
  session,
  userId,
}: {
  collection: string
  local: Store
  now: Date
  session: Store
  userId: number | string
}): boolean => {
  try {
    if (session.getItem(SESSION_KEY)) return false
    session.setItem(SESSION_KEY, '1')
    return enrolmentChoice(local, collection, userId, now) === null
  } catch {
    return false
  }
}
