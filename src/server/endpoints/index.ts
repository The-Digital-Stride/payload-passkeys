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

export const passkeyEndpoints = (options: ResolvedOptions, collectionSlug: string): Endpoint[] => [
  statusEndpoint(options, collectionSlug),
  registerOptionsEndpoint(options, collectionSlug),
  registerVerifyEndpoint(options, collectionSlug),
  signInOptionsEndpoint(options, collectionSlug),
  signInVerifyEndpoint(options, collectionSlug),
  reauthEndpoint(options, collectionSlug),
  renameEndpoint(options, collectionSlug),
  deleteEndpoint(options, collectionSlug),
]
