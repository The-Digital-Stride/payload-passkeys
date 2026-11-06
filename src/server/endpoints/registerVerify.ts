import { verifyRegistrationResponse } from '@simplewebauthn/server'
import { isoBase64URL } from '@simplewebauthn/server/helpers'

import type { ResolvedOptions } from '../options.js'
import type { PasskeyRow } from '../passkeyRecords.js'

import { providerName } from '../../shared/aaguid.js'
import { ENDPOINTS, MAX_PASSKEY_NAME, SUPPORTED_ALGORITHM_IDS } from '../../shared/constants.js'
import { ChallengeRejected, clearChallengeCookie, consumeChallenge } from '../challenges.js'
import { json, passkeyEndpoint } from '../http.js'
import { logEvent } from '../logging.js'
import {
  findPasskeyByCredentialId,
  listPasskeysOfUser,
  toPublicPasskey,
} from '../passkeyRecords.js'
import { challengeFromClientData, parseRegistrationResponse } from '../webauthnJson.js'

/** Printable text only, collapsed and cut to the field's limit. Empty means "use the default". */
export const cleanPasskeyName = (value: unknown): null | string => {
  if (typeof value !== 'string') return null
  const clean = value
    .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
  return clean ? clean.slice(0, MAX_PASSKEY_NAME) : null
}

const ZERO_AAGUID = '00000000-0000-0000-0000-000000000000'

export const registerVerifyEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'register.verify',
    auth: 'signed-in',
    collectionSlug,
    handler: async ({ body, req, user }) => {
      const clear = clearChallengeCookie(options, 'registration', collectionSlug)
      const refuse = (reason: string, credentialId?: string, status = 400) => {
        logEvent(req, options, 'passkeys.registration_failed', {
          collection: collectionSlug,
          credentialId,
          reason,
          userId: user.id,
        })
        return json(
          req,
          status,
          { error: status === 409 ? 'too_many_passkeys' : 'registration_failed' },
          [clear],
        )
      }

      const response = parseRegistrationResponse(body.response)
      if (!response) return refuse('malformed_response')
      const challenge = challengeFromClientData(response.response.clientDataJSON)
      if (!challenge) return refuse('malformed_client_data')

      let record
      try {
        record = await consumeChallenge({
          challenge,
          collection: collectionSlug,
          options,
          req,
          type: 'registration',
          userId: user.id,
        })
      } catch (error) {
        if (error instanceof ChallengeRejected) return refuse(error.reason)
        throw error
      }
      if (!record.userHandle) return refuse('challenge_without_user_handle')

      if (response.clientExtensionResults?.credProps?.rk === false)
        return refuse('not_discoverable', response.id)

      let verification
      try {
        verification = await verifyRegistrationResponse({
          expectedChallenge: challenge,
          expectedOrigin: options.origins,
          expectedRPID: options.rpID,
          requireUserVerification: true,
          response,
          supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
        })
      } catch (error) {
        return refuse(
          `verification_failed: ${error instanceof Error ? error.message.slice(0, 200) : 'unknown'}`,
          response.id,
        )
      }
      if (!verification.verified) return refuse('not_verified', response.id)
      const info = verification.registrationInfo

      if (
        (await listPasskeysOfUser(req, options, collectionSlug, user.id)).length >=
        options.limits.passkeysPerUser
      ) {
        return refuse('too_many_passkeys', info.credential.id, 409)
      }
      if (await findPasskeyByCredentialId(req, options, info.credential.id)) {
        return refuse('duplicate_credential', info.credential.id)
      }

      const aaguid = info.aaguid && info.aaguid !== ZERO_AAGUID ? info.aaguid : null
      let row: PasskeyRow
      try {
        row = (await req.payload.create({
          collection: options.slugs.passkeys as never,
          data: {
            aaguid,
            backedUp: info.credentialBackedUp,
            collection: collectionSlug,
            counter: info.credential.counter,
            credentialId: info.credential.id,
            deviceType: info.credentialDeviceType,
            lastUsedAt: null,
            name: cleanPasskeyName(body.name) ?? providerName(aaguid) ?? 'Passkey',
            publicKey: isoBase64URL.fromBuffer(info.credential.publicKey),
            rpID: options.rpID,
            transports: info.credential.transports ?? response.response.transports ?? [],
            user:
              options.collections.length === 1
                ? user.id
                : { relationTo: collectionSlug, value: user.id },
            userHandle: record.userHandle,
          } as never,
          depth: 0,
          overrideAccess: true,
          req,
        })) as unknown as PasskeyRow
      } catch {
        // The unique index on credentialId lost a race with a parallel registration.
        return refuse('duplicate_credential_race', info.credential.id)
      }

      logEvent(req, options, 'passkeys.registered', {
        aaguid,
        collection: collectionSlug,
        credentialId: row.credentialId,
        userId: user.id,
      })
      return json(req, 200, { passkey: toPublicPasskey(row) }, [clear])
    },
    options,
    path: ENDPOINTS.registerVerify,
  })
