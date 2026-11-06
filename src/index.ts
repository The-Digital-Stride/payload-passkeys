import type { Config } from 'payload'

import type { PasskeysPluginOptions } from './types.js'

import { challengesCollection } from './collections/challenges.js'
import { challengeUsesCollection } from './collections/challengeUses.js'
import { passkeysCollection } from './collections/passkeys.js'
import { withPasskeyFields } from './collections/userFields.js'
import { OPTIONS_KEY } from './server/context.js'
import { passkeyEndpoints } from './server/endpoints/index.js'
import { resolveOptions } from './server/options.js'

export type * from './types.js'

export const passkeysPlugin =
  (options: PasskeysPluginOptions = {}) =>
  (incoming: Config): Config => {
    const resolved = resolveOptions(incoming, options)
    const collections = (incoming.collections ?? []).map((collection) => {
      if (!resolved.collections.includes(collection.slug)) return collection
      const withFields = withPasskeyFields(collection, resolved)
      if (!resolved.enabled) return withFields
      return {
        ...withFields,
        endpoints: [
          ...(collection.endpoints || []),
          ...passkeyEndpoints(resolved, collection.slug),
        ],
      }
    })
    return {
      ...incoming,
      collections: [
        ...collections,
        passkeysCollection(resolved),
        challengesCollection(resolved),
        challengeUsesCollection(resolved),
      ],
      custom: { ...incoming.custom, [OPTIONS_KEY]: resolved },
    }
  }
