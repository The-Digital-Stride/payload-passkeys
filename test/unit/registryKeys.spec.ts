import { describe, expect, it } from 'vitest'

import { keysMatch } from '../../scripts/registry-keys-match.mjs'

// scripts/audit-signatures.sh re-runs npm audit signatures against registry.npmjs.com only when
// that host's /-/npm/v1/keys are exactly the keys Sigstore's TUF repository distributes for
// registry.npmjs.org (what npm itself trusts for the default registry).

const OLD = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEold'
const NEW = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnew'

const tufKey = (keyId: string, rawBytes: string, usage: string, end?: string) => ({
  keyId,
  keyUsage: usage,
  publicKey: {
    keyDetails: 'PKIX_ECDSA_P256_SHA_256',
    rawBytes,
    validFor: { end, start: '2022-01-01T00:00:00.000Z' },
  },
})
const tuf = {
  keys: [
    tufKey('SHA256:old', OLD, 'npm:signatures', '2025-01-29T00:00:00.000Z'),
    tufKey('SHA256:old', OLD, 'npm:attestations', '2025-01-29T00:00:00.000Z'),
    tufKey('SHA256:new', NEW, 'npm:signatures'),
    tufKey('SHA256:new', NEW, 'npm:attestations'),
  ],
}
const apiKey = (keyid: string, key: string, expires: null | string) => ({
  expires,
  key,
  keyid,
  keytype: 'ecdsa-sha2-nistp256',
  scheme: 'ecdsa-sha2-nistp256',
})
const api = {
  keys: [apiKey('SHA256:old', OLD, '2025-01-29T00:00:00.000Z'), apiKey('SHA256:new', NEW, null)],
}

describe('keysMatch', () => {
  it('accepts the same keys, ids and expiry dates', () => {
    expect(keysMatch(tuf, api)).toEqual({ ok: true })
  })

  it('refuses a key whose bytes differ', () => {
    const swapped = { keys: [api.keys[0], apiKey('SHA256:new', 'MFkwattacker', null)] }
    expect(keysMatch(tuf, swapped).ok).toBe(false)
  })

  it('refuses an extra key the TUF list does not have', () => {
    const extra = { keys: [...api.keys, apiKey('SHA256:extra', 'MFkwextra', null)] }
    expect(keysMatch(tuf, extra).ok).toBe(false)
  })

  it('refuses a missing key', () => {
    expect(keysMatch(tuf, { keys: [api.keys[1]] }).ok).toBe(false)
  })

  it('refuses an expired key presented as never expiring', () => {
    const revived = { keys: [apiKey('SHA256:old', OLD, null), api.keys[1]] }
    expect(keysMatch(tuf, revived).ok).toBe(false)
  })

  it('refuses a TUF list whose usages disagree about one key id', () => {
    const odd = { keys: [...tuf.keys, tufKey('SHA256:new', 'MFkwother', 'npm:attestations')] }
    expect(keysMatch(odd, api).ok).toBe(false)
  })

  it('refuses empty or malformed input', () => {
    expect(keysMatch({ keys: [] }, { keys: [] }).ok).toBe(false)
    expect(keysMatch({}, api).ok).toBe(false)
    expect(keysMatch(tuf, { keys: 'nope' }).ok).toBe(false)
  })
})
