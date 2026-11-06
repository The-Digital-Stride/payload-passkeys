import { describe, expect, it } from 'vitest'

import {
  enrolmentChoice,
  rememberChoice,
  shouldOfferEnrolment,
} from '../../src/components/shared/enrolmentStorage.js'

const store = () => {
  const map = new Map<string, string>()
  return {
    getItem: (k: string) => map.get(k) ?? null,
    removeItem: (k: string) => void map.delete(k),
    setItem: (k: string, v: string) => void map.set(k, v),
  }
}

describe('enrolment prompt storage', () => {
  const now = new Date('2026-11-06T12:00:00Z')
  it('offers by default, once per browser session', () => {
    const local = store()
    const session = store()
    expect(shouldOfferEnrolment({ collection: 'users', local, now, session, userId: 1 })).toBe(true)
    expect(shouldOfferEnrolment({ collection: 'users', local, now, session, userId: 1 })).toBe(
      false,
    )
  })
  it('"Not now" hides it for 30 days for that user', () => {
    const local = store()
    rememberChoice(local, 'users', 1, 'not-now', now)
    expect(enrolmentChoice(local, 'users', 1, new Date('2026-12-05T12:00:00Z'))).toBe('not-now')
    expect(enrolmentChoice(local, 'users', 1, new Date('2026-12-06T12:00:01Z'))).toBeNull()
    expect(enrolmentChoice(local, 'users', 2, now)).toBeNull()
  })
  it('"Don\'t ask again" sticks', () => {
    const local = store()
    rememberChoice(local, 'users', 1, 'never', now)
    expect(
      shouldOfferEnrolment({
        collection: 'users',
        local,
        now: new Date('2030-01-01'),
        session: store(),
        userId: 1,
      }),
    ).toBe(false)
  })
  it('survives storage that throws (private mode)', () => {
    const broken = {
      getItem: () => {
        throw new Error('denied')
      },
      removeItem: () => {},
      setItem: () => {
        throw new Error('denied')
      },
    }
    expect(
      shouldOfferEnrolment({ collection: 'users', local: broken, now, session: broken, userId: 1 }),
    ).toBe(false)
  })
})
