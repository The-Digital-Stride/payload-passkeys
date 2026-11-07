import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server'
import { isoBase64URL } from '@simplewebauthn/server/helpers'
import { describe, expect, it } from 'vitest'

import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'

const origin = 'http://localhost:3000'
const rpID = 'localhost'

const setUp = async (options: Parameters<typeof createSoftAuthenticator>[0] = { origin }) => {
  const authenticator = createSoftAuthenticator(options)
  const regOptions = await generateRegistrationOptions({
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    rpID,
    rpName: 'Test',
    userID: isoBase64URL.toBuffer('dXNlci1oYW5kbGU'),
    userName: 'a@example.test',
  })
  const registration = await verifyRegistrationResponse({
    expectedChallenge: regOptions.challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    requireUserVerification: true,
    response: await authenticator.register(regOptions),
  })
  if (!registration.verified) throw new Error('registration failed')
  const credential = registration.registrationInfo.credential
  const assert = async (overrides: Parameters<typeof authenticator.authenticate>[1] = {}) => {
    const authOptions = await generateAuthenticationOptions({ rpID, userVerification: 'required' })
    const response = await authenticator.authenticate(authOptions, overrides)
    return {
      response,
      result: await verifyAuthenticationResponse({
        credential: { ...credential, counter: 0 },
        expectedChallenge: authOptions.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: true,
        response,
      }),
    }
  }
  return { assert, authenticator, registration }
}

describe('soft authenticator', () => {
  it('registers a synced passkey by default', async () => {
    const { registration } = await setUp({ aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4', origin })
    expect(registration.registrationInfo).toMatchObject({
      aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4',
      credentialBackedUp: true,
      credentialDeviceType: 'multiDevice',
    })
  })

  it('registers a device-bound passkey with BE=0', async () => {
    const { registration } = await setUp({ backupEligible: false, origin })
    expect(registration.registrationInfo).toMatchObject({
      credentialBackedUp: false,
      credentialDeviceType: 'singleDevice',
    })
  })

  it('asserts, and the user handle round-trips', async () => {
    const { assert } = await setUp()
    const { response, result } = await assert()
    expect(result.verified).toBe(true)
    expect(response.response.userHandle).toBe('dXNlci1oYW5kbGU')
  })

  it('reports the real counter when the library is given 0', async () => {
    const { assert } = await setUp({ incrementCounter: true, origin })
    await assert()
    expect((await assert()).result.authenticationInfo.newCounter).toBe(2)
  })

  it.each([
    [{ userVerified: false }, /User verification/],
    [{ origin: 'https://evil.test' }, /origin/],
    [{ rpID: 'evil.test' }, /RP ID/],
    [{ type: 'webauthn.create' }, /type/],
  ])('fails with %j', async (overrides, message) => {
    const { assert } = await setUp()
    await expect(assert(overrides)).rejects.toThrow(message)
  })

  it('produces an unverifiable signature on request', async () => {
    const { assert } = await setUp()
    expect((await assert({ badSignature: true })).result.verified).toBe(false)
  })
})
