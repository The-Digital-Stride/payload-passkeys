import type { DeviceType } from '../types.js'

export type CounterDecision =
  | { action: 'accept'; backedUp: boolean; counter: number; regression: boolean }
  | { action: 'refuse'; reason: 'counter_not_increased' | 'device_type_changed' }

/**
 * SimpleWebAuthn is always given counter 0 (it throws on any non-increase otherwise), and this
 * decides instead (review M7):
 * - BE (device type) must never change;
 * - a device-bound passkey must increase its counter unless both values are 0;
 * - a synced passkey may regress (several devices share it): log it, keep the higher value;
 * - the stored counter never goes down; backedUp follows BS.
 */
export const decideCounter = (
  stored: { backedUp: boolean; counter: number; deviceType: DeviceType },
  reported: { backedUp: boolean; deviceType: DeviceType; newCounter: number },
): CounterDecision => {
  if (reported.deviceType !== stored.deviceType)
    return { action: 'refuse', reason: 'device_type_changed' }
  const bothZero = stored.counter === 0 && reported.newCounter === 0
  const increased = reported.newCounter > stored.counter
  if (!increased && !bothZero) {
    if (stored.deviceType === 'singleDevice')
      return { action: 'refuse', reason: 'counter_not_increased' }
    return {
      action: 'accept',
      backedUp: reported.backedUp,
      counter: stored.counter,
      regression: true,
    }
  }
  return {
    action: 'accept',
    backedUp: reported.backedUp,
    counter: Math.max(stored.counter, reported.newCounter),
    regression: false,
  }
}
