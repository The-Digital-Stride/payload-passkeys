import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  ceremoniesDisabledReason,
  RECHECK_INTERVAL_MS,
  RECHECK_WAIT_MS,
  refreshCeremoniesDisabled,
  setCeremoniesDisabled,
} from '../../src/server/health.js'

/** A re-check the test settles by hand. */
const deferredRecheck = () => {
  let settle: (healthy: boolean) => void = () => {}
  const recheck = vi.fn(
    () =>
      new Promise<boolean>((resolve) => {
        settle = resolve
      }),
  )
  return { recheck, settle: (healthy: boolean) => settle(healthy) }
}

describe('refreshCeremoniesDisabled', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('answers null without re-checking while ceremonies are on', async () => {
    const payload = {}
    expect(await refreshCeremoniesDisabled(payload)).toBeNull()
  })

  it('turns ceremonies back on once the re-check passes', async () => {
    const payload = {}
    const recheck = vi.fn(async () => true)
    setCeremoniesDisabled(payload, 'indexes', recheck)
    expect(await refreshCeremoniesDisabled(payload)).toBeNull()
    expect(recheck).toHaveBeenCalledTimes(1)
    expect(ceremoniesDisabledReason(payload)).toBeNull()
  })

  it('stays off while the re-check fails, and re-checks at most once per interval', async () => {
    const payload = {}
    const recheck = vi.fn(async () => false)
    setCeremoniesDisabled(payload, 'indexes', recheck)
    expect(await refreshCeremoniesDisabled(payload)).toBe('indexes')
    expect(await refreshCeremoniesDisabled(payload)).toBe('indexes')
    vi.advanceTimersByTime(RECHECK_INTERVAL_MS - 1)
    expect(await refreshCeremoniesDisabled(payload)).toBe('indexes')
    expect(recheck).toHaveBeenCalledTimes(1)

    vi.advanceTimersByTime(1)
    recheck.mockResolvedValueOnce(true)
    expect(await refreshCeremoniesDisabled(payload)).toBeNull()
    expect(recheck).toHaveBeenCalledTimes(2)
  })

  it('stays off when the re-check throws', async () => {
    const payload = {}
    setCeremoniesDisabled(
      payload,
      'indexes',
      vi.fn(async () => {
        throw new Error('pool cleared')
      }),
    )
    expect(await refreshCeremoniesDisabled(payload)).toBe('indexes')
  })

  it('runs one re-check for concurrent requests', async () => {
    const payload = {}
    const { recheck, settle } = deferredRecheck()
    setCeremoniesDisabled(payload, 'indexes', recheck)
    const answers = Promise.all([
      refreshCeremoniesDisabled(payload),
      refreshCeremoniesDisabled(payload),
      refreshCeremoniesDisabled(payload),
    ])
    settle(true)
    expect(await answers).toEqual([null, null, null])
    expect(recheck).toHaveBeenCalledTimes(1)
  })

  it('answers with the current state when a re-check is slow, and applies it later', async () => {
    const payload = {}
    const { recheck, settle } = deferredRecheck()
    setCeremoniesDisabled(payload, 'indexes', recheck)
    const answer = refreshCeremoniesDisabled(payload)
    await vi.advanceTimersByTimeAsync(RECHECK_WAIT_MS)
    expect(await answer).toBe('indexes')

    settle(true)
    await vi.advanceTimersByTimeAsync(0)
    expect(ceremoniesDisabledReason(payload)).toBeNull()
    expect(recheck).toHaveBeenCalledTimes(1)
  })

  it('does not clear a state set again while its re-check ran', async () => {
    const payload = {}
    const first = deferredRecheck()
    setCeremoniesDisabled(payload, 'indexes', first.recheck)
    const answer = refreshCeremoniesDisabled(payload)
    // A second boot on the same instance found the indexes missing again.
    setCeremoniesDisabled(
      payload,
      'indexes',
      vi.fn(async () => false),
    )
    first.settle(true)
    await answer
    expect(ceremoniesDisabledReason(payload)).toBe('indexes')
  })

  it('stays off with no re-check to run', async () => {
    const payload = {}
    setCeremoniesDisabled(payload, 'indexes')
    expect(await refreshCeremoniesDisabled(payload)).toBe('indexes')
  })
})
