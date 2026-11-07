import { generateAuthenticationOptions } from '@simplewebauthn/server'

import type { ResolvedOptions } from '../options.js'

import { CEREMONY_TIMEOUT_MS, ENDPOINTS } from '../../shared/constants.js'
import { ChallengeCapReached, issueChallenge } from '../challenges.js'
import { json, passkeyEndpoint } from '../http.js'

/** Discoverable sign-in: no account named, nothing about accounts revealed (design §4.2). */
export const signInOptionsEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    ceremony: true,
    action: 'sign-in.options',
    auth: 'anonymous',
    collectionSlug,
    handler: async ({ req }) => {
      const request = await generateAuthenticationOptions({
        allowCredentials: [],
        rpID: options.rpID,
        timeout: CEREMONY_TIMEOUT_MS,
        userVerification: 'required',
      })
      try {
        const { setCookie } = await issueChallenge({
          challenge: request.challenge,
          collection: collectionSlug,
          options,
          req,
          type: 'authentication',
        })
        return json(req, 200, { options: request }, [setCookie])
      } catch (error) {
        if (error instanceof ChallengeCapReached) return json(req, 429, { error: 'busy' })
        throw error
      }
    },
    options,
    path: ENDPOINTS.signInOptions,
  })
