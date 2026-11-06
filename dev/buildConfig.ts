import type { CollectionConfig, Config } from 'payload'

import { buildConfig } from 'payload'
import path from 'path'
import { fileURLToPath } from 'url'

import type { PasskeysPluginOptions } from '../src/index.js'

import { passkeysPlugin } from '../src/index.js'
import { databaseAdapter } from './db.js'
import { testEmailAdapter } from './helpers/testEmailAdapter.js'
import { seed } from './seed.js'
import { testHooks } from './testHooks.js'

const dirname = path.dirname(fileURLToPath(import.meta.url))
export const SERVER_URL = process.env.PAYLOAD_PUBLIC_SERVER_URL ?? 'http://localhost:3000'

const hookFields = {
  hooks: {
    afterLogin: [(args: Record<string, unknown>) => testHooks.afterLogin?.(args) as undefined],
    beforeLogin: [(args: Record<string, unknown>) => testHooks.beforeLogin?.(args) as undefined],
  },
}

const users: CollectionConfig = {
  slug: 'users',
  admin: { useAsTitle: 'name' },
  auth: { lockTime: 600_000, maxLoginAttempts: 5, useAPIKey: true },
  fields: [{ name: 'name', type: 'text' }],
  ...hookFields,
}

const customers: CollectionConfig = {
  slug: 'customers',
  admin: { useAsTitle: 'email' },
  auth: { removeTokenFromResponses: true, verify: true },
  fields: [],
  ...hookFields,
}

export const buildDevConfig = ({
  plugin = {},
  variant = 'single',
}: { plugin?: PasskeysPluginOptions; variant?: 'multi' | 'single' } = {}) =>
  buildConfig({
    admin: { importMap: { baseDir: path.resolve(dirname) }, user: 'users' },
    collections: variant === 'multi' ? [users, customers] : [users],
    // 127.0.0.1 stands in for a preview host: same app, not under the RP ID (Tasks 21 and 36).
    csrf: [SERVER_URL, 'http://127.0.0.1:3000'],
    db: databaseAdapter(),
    email: testEmailAdapter,
    onInit: async (payload) => {
      if (process.env.NODE_ENV !== 'test') await seed(payload)
    },
    plugins: [
      passkeysPlugin({
        // Task 11 types these options; until then the plugin takes none.
        // collections: variant === 'multi' ? ['users', 'customers'] : ['users'],
        // onSignIn: (args) => testHooks.onSignIn?.(args as Record<string, unknown>) as undefined,
        ...plugin,
      }),
    ],
    secret: process.env.PAYLOAD_SECRET ?? 'dev-only-secret-change-me',
    serverURL: SERVER_URL,
    typescript: {
      // Payload spawns `payload generate:types` on every init outside production; under Vitest
      // that child outlives the run and spins, one per test file.
      autoGenerate: !process.env.VITEST,
      outputFile: path.resolve(dirname, 'payload-types.ts'),
    },
  } satisfies Config)
