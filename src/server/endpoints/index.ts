import type { Endpoint } from 'payload'

import type { ResolvedOptions } from '../options.js'

import { reauthEndpoint } from './reauth.js'
import { registerOptionsEndpoint } from './registerOptions.js'
import { registerVerifyEndpoint } from './registerVerify.js'
import { signInOptionsEndpoint } from './signInOptions.js'
import { signInVerifyEndpoint } from './signInVerify.js'

export const passkeyEndpoints = (options: ResolvedOptions, collectionSlug: string): Endpoint[] => [
  registerOptionsEndpoint(options, collectionSlug),
  registerVerifyEndpoint(options, collectionSlug),
  reauthEndpoint(options, collectionSlug),
  signInOptionsEndpoint(options, collectionSlug),
  signInVerifyEndpoint(options, collectionSlug),
]
