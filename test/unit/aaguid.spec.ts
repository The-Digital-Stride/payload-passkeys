import { describe, expect, it } from 'vitest'

import { providerName } from '../../src/shared/aaguid.js'
import { AAGUID_NAMES } from '../../src/shared/aaguids.generated.js'

describe('providerName', () => {
  it.each([
    ['ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4', 'Google Password Manager'],
    ['fbfc3007-154e-4ecc-8c0b-6e020557d7bd', 'Apple Passwords'],
    ['bada5566-a7aa-401f-bd96-45619a55120d', '1Password'],
    ['08987058-cadc-4b81-b6e1-30de50dcbe96', 'Windows Hello'],
    ['EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4', 'Google Password Manager'],
  ])('names %s', (aaguid, name) => {
    expect(providerName(aaguid)).toBe(name)
  })
  it('returns null for unknown, zero and missing AAGUIDs', () => {
    expect(providerName('00000000-0000-0000-0000-000000000000')).toBeNull()
    expect(providerName('12345678-1234-1234-1234-123456789abc')).toBeNull()
    expect(providerName(null)).toBeNull()
  })
  it('vendors the agreed providers and nothing else', () => {
    expect(new Set(Object.values(AAGUID_NAMES)).size).toBe(20)
  })
})
