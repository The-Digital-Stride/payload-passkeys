import { verifyAuthenticationResponse } from '@simplewebauthn/server'
import { isoBase64URL } from '@simplewebauthn/server/helpers'

import type { ResolvedOptions } from '../options.js'

import { ENDPOINTS } from '../../shared/constants.js'
import { ChallengeRejected, clearChallengeCookie, consumeChallenge } from '../challenges.js'
import { decideCounter } from '../counterPolicy.js'
import { verifyAgainstDummy } from '../dummyCredential.js'
import { json, passkeyEndpoint } from '../http.js'
import { logEvent } from '../logging.js'
import { mintSession, SignInRefused } from '../mintSession.js'
import { findPasskeyByCredentialId, ownerOf, toPublicPasskey } from '../passkeyRecords.js'
import { challengeFromClientData, parseAuthenticationResponse } from '../webauthnJson.js'

export const signInVerifyEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    ceremony: true,
    action: 'sign-in.verify',
    auth: 'anonymous',
    collectionSlug,
    handler: async ({ body, req }) => {
      const clear = clearChallengeCookie(options, 'authentication', collectionSlug)
      const base = { collection: collectionSlug }
      /** Every failure looks the same to the browser; the reason goes to the log only. */
      const refuse = (
        reason: string,
        extra: {
          aaguid?: null | string
          credentialId?: string
          unknownCredential?: boolean
          userId?: number | string
        } = {},
      ) => {
        const { unknownCredential, ...fields } = extra
        logEvent(
          req,
          options,
          unknownCredential ? 'passkeys.unknown_credential' : 'passkeys.sign_in_failed',
          { ...base, ...fields, reason },
        )
        return json(
          req,
          400,
          { error: 'sign_in_failed', ...(unknownCredential ? { unknownCredential: true } : {}) },
          [clear],
        )
      }

      const response = parseAuthenticationResponse(body.response)
      if (!response) return refuse('malformed_response')
      const challenge = challengeFromClientData(response.response.clientDataJSON)
      if (!challenge) return refuse('malformed_client_data')

      try {
        await consumeChallenge({
          challenge,
          collection: collectionSlug,
          options,
          req,
          type: 'authentication',
        })
      } catch (error) {
        if (error instanceof ChallengeRejected) return refuse(error.reason)
        throw error
      }

      const row = await findPasskeyByCredentialId(req, options, response.id)
      if (!row) {
        await verifyAgainstDummy(response, challenge, options)
        return refuse('unknown_credential', { credentialId: response.id, unknownCredential: true })
      }
      const ids = { aaguid: row.aaguid ?? null, credentialId: row.credentialId }

      // Collection first: on SQL, users 7 and customers 7 can both exist (H3).
      if (row.authCollection !== collectionSlug) {
        await verifyAgainstDummy(response, challenge, options)
        return refuse('wrong_collection', ids)
      }
      const owner = ownerOf(row)
      if (!owner || owner.collection !== collectionSlug) return refuse('owner_mismatch', ids)
      const withUser = { ...ids, userId: owner.id }

      if (!response.response.userHandle || response.response.userHandle !== row.userHandle) {
        return refuse('user_handle_mismatch', withUser)
      }

      let verification
      try {
        verification = await verifyAuthenticationResponse({
          // Counter 0: the library would throw on any non-increase; decideCounter applies the policy (M7).
          credential: {
            counter: 0,
            id: row.credentialId,
            publicKey: isoBase64URL.toBuffer(row.publicKey),
            transports: (row.transports ?? undefined) as never,
          },
          expectedChallenge: challenge,
          expectedOrigin: options.origins,
          expectedRPID: options.rpID,
          requireUserVerification: true,
          response,
        })
      } catch (error) {
        return refuse(
          `verification_failed: ${error instanceof Error ? error.message.slice(0, 200) : 'unknown'}`,
          withUser,
        )
      }
      if (!verification.verified) return refuse('bad_signature', withUser)
      const info = verification.authenticationInfo

      const decision = decideCounter(
        { backedUp: Boolean(row.backedUp), counter: row.counter ?? 0, deviceType: row.deviceType },
        {
          backedUp: info.credentialBackedUp,
          deviceType: info.credentialDeviceType,
          newCounter: info.newCounter,
        },
      )
      if (decision.action === 'refuse') return refuse(decision.reason, withUser)
      if (decision.regression)
        logEvent(req, options, 'passkeys.counter_regression', { ...base, ...withUser })

      await req.payload.db.updateOne({
        collection: options.slugs.passkeys,
        data: {
          backedUp: decision.backedUp,
          counter: decision.counter,
          lastUsedAt: new Date().toISOString(),
        },
        id: row.id,
        req,
        returning: false,
      })

      let minted
      try {
        minted = await mintSession({
          collectionSlug,
          onSignIn: options.onSignIn,
          passkey: toPublicPasskey(row),
          req,
          userId: owner.id,
        })
      } catch (error) {
        const reason =
          error instanceof SignInRefused
            ? error.reason
            : `refused_by_hook: ${error instanceof Error ? error.name : 'unknown'}`
        return refuse(reason, withUser)
      }

      if (minted.wasLocked)
        logEvent(req, options, 'passkeys.signed_in_while_locked', { ...base, ...withUser })
      logEvent(req, options, 'passkeys.signed_in', { ...base, ...withUser })
      return json(req, 200, minted.body, [minted.setCookie, clear])
    },
    options,
    path: ENDPOINTS.signInVerify,
  })
