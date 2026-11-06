import { verifyAuthenticationResponse } from '@simplewebauthn/server'
import { isoCBOR } from '@simplewebauthn/server/helpers'

import type { AuthenticationResponseJSON } from '@simplewebauthn/server'

import type { ResolvedOptions } from './options.js'

let dummyKey: Promise<Uint8Array> | undefined

/** A COSE ES256 public key made once per process. Nothing can sign for it. */
const dummyPublicKey = (): Promise<Uint8Array> =>
  (dummyKey ??= (async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
    return isoCBOR.encode(
      new Map<number, number | Uint8Array>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, raw.slice(1, 33)],
        [-3, raw.slice(33, 65)],
      ]),
    )
  })())

/**
 * Runs the same verification as a known credential against a key nobody holds, so an unknown
 * credential takes about as long to refuse as a known one (review L6). Always resolves.
 */
export const verifyAgainstDummy = async (
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
  options: Pick<ResolvedOptions, 'origins' | 'rpID'>,
): Promise<void> => {
  try {
    await verifyAuthenticationResponse({
      credential: {
        counter: 0,
        id: response.id,
        publicKey: (await dummyPublicKey()) as Uint8Array<ArrayBuffer>,
      },
      expectedChallenge,
      expectedOrigin: options.origins,
      expectedRPID: options.rpID,
      requireUserVerification: true,
      response,
    })
  } catch {
    // Expected: the signature can't verify.
  }
}
