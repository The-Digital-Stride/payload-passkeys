import type { Config } from 'payload'

import { existsSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

import type { PasskeysPluginOptions } from './types.js'

import { challengesCollection } from './collections/challenges.js'
import { challengeUsesCollection } from './collections/challengeUses.js'
import { passkeysCollection } from './collections/passkeys.js'
import { withPasskeyFields } from './collections/userFields.js'
import { OPTIONS_KEY } from './server/context.js'
import { passkeyEndpoints } from './server/endpoints/index.js'
import { resolveOptions } from './server/options.js'
import { withPasskeysTranslations } from './translations/index.js'

export type * from './types.js'

const here = path.dirname(fileURLToPath(import.meta.url))
/** dist/bin/reset.js when published, src/bin/reset.ts in this repo. */
const resetScriptPath = ['bin/reset.js', 'bin/reset.ts']
  .map((file) => path.join(here, file))
  .find((file) => existsSync(file))

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
      // Always, even when disabled: recovery must work whatever the plugin's state (review M6).
      bin: [
        ...(incoming.bin ?? []),
        ...(resetScriptPath ? [{ key: 'passkeys:reset', scriptPath: resetScriptPath }] : []),
      ],
      collections: [
        ...collections,
        passkeysCollection(resolved),
        challengesCollection(resolved),
        challengeUsesCollection(resolved),
      ],
      custom: { ...incoming.custom, [OPTIONS_KEY]: resolved },
      // Always, even when disabled: the schema's admin text stays translatable.
      i18n: withPasskeysTranslations(incoming.i18n),
    }
  }
