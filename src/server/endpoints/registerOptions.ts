import { generateRegistrationOptions } from '@simplewebauthn/server'
import { isoBase64URL } from '@simplewebauthn/server/helpers'

import type { ResolvedOptions } from '../options.js'

import { CEREMONY_TIMEOUT_MS, ENDPOINTS, SUPPORTED_ALGORITHM_IDS } from '../../shared/constants.js'
import { issueChallenge } from '../challenges.js'
import { EndpointError, json, passkeyEndpoint } from '../http.js'
import { logEvent } from '../logging.js'
import { authCollectionConfig, loadRawUser } from '../mintSession.js'
import { listPasskeysOfUser } from '../passkeyRecords.js'
import { ensureUserHandle, isFreshSession, webauthnUserNames } from '../userInfo.js'

export const registerOptionsEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    ceremony: true,
    action: 'register.options',
    auth: 'signed-in',
    collectionSlug,
    handler: async ({ req, user }) => {
      const raw = await loadRawUser(req, collectionSlug, user.id)
      if (!raw) throw new EndpointError(401, 'unauthorised')
      if (!isFreshSession(raw, user._sid, options.freshSessionMs)) {
        logEvent(req, options, 'passkeys.reauth_required', {
          collection: collectionSlug,
          userId: user.id,
        })
        return json(req, 403, { error: 'reauth_required' })
      }
      const existing = await listPasskeysOfUser(req, options, collectionSlug, user.id)
      if (existing.length >= options.limits.passkeysPerUser)
        throw new EndpointError(409, 'too_many_passkeys')

      const userHandle = await ensureUserHandle(req, collectionSlug, raw)
      const { displayName, name } = webauthnUserNames(
        authCollectionConfig(req, collectionSlug),
        raw,
      )
      const creation = await generateRegistrationOptions({
        attestationType: 'none',
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        excludeCredentials: existing.map((p) => ({
          id: p.credentialId,
          transports: p.transports ?? undefined,
        })),
        extensions: { credProps: true },
        rpID: options.rpID,
        rpName: options.rpName,
        supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
        timeout: CEREMONY_TIMEOUT_MS,
        userDisplayName: displayName,
        userID: isoBase64URL.toBuffer(userHandle),
        userName: name,
      })
      const { setCookie } = await issueChallenge({
        challenge: creation.challenge,
        collection: collectionSlug,
        options,
        req,
        type: 'registration',
        userHandle,
        userId: user.id,
      })
      return json(req, 200, { options: creation }, [setCookie])
    },
    options,
    path: ENDPOINTS.registerOptions,
  })
