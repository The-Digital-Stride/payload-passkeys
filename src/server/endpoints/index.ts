import type { Endpoint } from 'payload'

import type { ResolvedOptions } from '../options.js'

import { deleteEndpoint } from './delete.js'
import { reauthEndpoint } from './reauth.js'
import { registerOptionsEndpoint } from './registerOptions.js'
import { registerVerifyEndpoint } from './registerVerify.js'
import { renameEndpoint } from './rename.js'
import { signInOptionsEndpoint } from './signInOptions.js'
import { signInVerifyEndpoint } from './signInVerify.js'
import { statusEndpoint } from './status.js'

/**
 * The reauth endpoint (password re-entry) exists only in 'password' mode: with 'sign-in-again'
 * there is no password to check, and an endpoint that counts wrong guesses would let a guesser
 * lock out an SSO admin.
 */
export const passkeyEndpoints = (options: ResolvedOptions, collectionSlug: string): Endpoint[] => [
  statusEndpoint(options, collectionSlug),
  registerOptionsEndpoint(options, collectionSlug),
  registerVerifyEndpoint(options, collectionSlug),
  signInOptionsEndpoint(options, collectionSlug),
  signInVerifyEndpoint(options, collectionSlug),
  ...(options.reauthentication === 'password' ? [reauthEndpoint(options, collectionSlug)] : []),
  renameEndpoint(options, collectionSlug),
  deleteEndpoint(options, collectionSlug),
]
