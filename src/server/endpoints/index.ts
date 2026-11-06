import type { Endpoint } from 'payload'

import type { ResolvedOptions } from '../options.js'

import { reauthEndpoint } from './reauth.js'
import { registerOptionsEndpoint } from './registerOptions.js'

export const passkeyEndpoints = (options: ResolvedOptions, collectionSlug: string): Endpoint[] => [
  registerOptionsEndpoint(options, collectionSlug),
  reauthEndpoint(options, collectionSlug),
]
