import { describe, expect, it } from 'vitest'

import { decideCounter } from '../../src/server/counterPolicy.js'

const stored = (
  counter: number,
  deviceType: 'multiDevice' | 'singleDevice',
  backedUp = deviceType === 'multiDevice',
) => ({ backedUp, counter, deviceType })
const reported = (
  newCounter: number,
  deviceType: 'multiDevice' | 'singleDevice',
  backedUp = deviceType === 'multiDevice',
) => ({ backedUp, deviceType, newCounter })

describe('decideCounter (review M7)', () => {
  it('accepts zero counters (synced passkeys report 0)', () => {
    expect(decideCounter(stored(0, 'multiDevice'), reported(0, 'multiDevice'))).toEqual({
      action: 'accept',
      backedUp: true,
      counter: 0,
      regression: false,
    })
  })
  it('accepts an increase and stores it', () => {
    expect(decideCounter(stored(5, 'singleDevice'), reported(6, 'singleDevice'))).toMatchObject({
      action: 'accept',
      counter: 6,
      regression: false,
    })
  })
  it('refuses a device-bound passkey whose counter did not increase', () => {
    expect(decideCounter(stored(5, 'singleDevice'), reported(5, 'singleDevice'))).toEqual({
      action: 'refuse',
      reason: 'counter_not_increased',
    })
    expect(decideCounter(stored(5, 'singleDevice'), reported(0, 'singleDevice'))).toEqual({
      action: 'refuse',
      reason: 'counter_not_increased',
    })
  })
  it('lets a synced passkey through a regression but never lowers the stored counter', () => {
    expect(decideCounter(stored(9, 'multiDevice'), reported(3, 'multiDevice'))).toEqual({
      action: 'accept',
      backedUp: true,
      counter: 9,
      regression: true,
    })
  })
  it('refuses a change of device type (BE must never change)', () => {
    expect(decideCounter(stored(0, 'multiDevice'), reported(0, 'singleDevice'))).toEqual({
      action: 'refuse',
      reason: 'device_type_changed',
    })
    expect(decideCounter(stored(0, 'singleDevice'), reported(1, 'multiDevice'))).toEqual({
      action: 'refuse',
      reason: 'device_type_changed',
    })
  })
  it('follows the backup state', () => {
    expect(
      decideCounter(stored(0, 'multiDevice', false), reported(0, 'multiDevice', true)),
    ).toMatchObject({ backedUp: true })
    expect(
      decideCounter(stored(0, 'multiDevice', true), reported(0, 'multiDevice', false)),
    ).toMatchObject({ backedUp: false })
  })
})
