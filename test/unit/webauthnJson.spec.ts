import { describe, expect, it } from 'vitest'

import {
  challengeFromClientData,
  parseAuthenticationResponse,
  parseRegistrationResponse,
} from '../../src/server/webauthnJson.js'

const b64 = (value: string) => Buffer.from(value).toString('base64url')
const challenge = 'A'.repeat(43)

describe('challengeFromClientData', () => {
  it('reads a 43-character base64url challenge', () => {
    expect(challengeFromClientData(b64(JSON.stringify({ challenge, type: 'webauthn.get' })))).toBe(
      challenge,
    )
  })
  it.each([
    b64('{'),
    b64(JSON.stringify({ challenge: 'short' })),
    b64(JSON.stringify({ challenge: 'A'.repeat(42) + '=' })),
    '***',
    42,
  ])('returns null for %j', (value) => {
    expect(challengeFromClientData(value)).toBeNull()
  })
})

describe('parse responses', () => {
  const auth = {
    authenticatorAttachment: 'platform',
    clientExtensionResults: {},
    id: 'abc',
    rawId: 'abc',
    response: { authenticatorData: 'AA', clientDataJSON: 'AA', signature: 'AA', userHandle: 'AA' },
    type: 'public-key',
    extra: 'dropped',
  }
  it('keeps only known keys', () => {
    expect(parseAuthenticationResponse(auth)).not.toHaveProperty('extra')
  })
  it.each([
    { ...auth, type: 'password' },
    { ...auth, rawId: 'other' },
    { ...auth, id: 'a+b' },
    { ...auth, id: 'A'.repeat(1400), rawId: 'A'.repeat(1400) },
    { ...auth, response: { ...auth.response, signature: 7 } },
    null,
    [],
  ])('refuses a malformed assertion (%#)', (value) => {
    expect(parseAuthenticationResponse(value)).toBeNull()
  })
  it('refuses a malformed attestation', () => {
    expect(parseRegistrationResponse({ ...auth, response: { clientDataJSON: 'AA' } })).toBeNull()
    expect(
      parseRegistrationResponse({
        ...auth,
        response: { attestationObject: 'AA', clientDataJSON: 'AA', transports: ['internal', 7] },
      }),
    ).toBeNull()
  })
})
