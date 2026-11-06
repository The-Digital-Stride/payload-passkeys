import type { CollectionConfig, Config, Endpoint } from 'payload'

import { buildConfig } from 'payload'
import path from 'path'
import { fileURLToPath } from 'url'

import type { PasskeysPluginOptions } from '../src/index.js'

import { passkeysPlugin } from '../src/index.js'
import type { DatabaseOptions } from './db.js'

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

const SESSION_AGE_MS = 30 * 60 * 1000

/**
 * E2E only (Task 36), and never in src/: moves the caller's own current session 30 minutes into
 * the past, so the fresh-session rule asks for the password. Only a signed-in cookie session of
 * this collection may call it, and it touches no other session or account.
 */
const ageSessionEndpoint: Endpoint = {
  handler: async (req) => {
    const user = req.user as { _sid?: unknown; _strategy?: unknown; collection?: unknown } | null
    const sid = user?._sid
    if (
      !req.user ||
      user?.collection !== 'users' ||
      user._strategy !== 'local-jwt' ||
      typeof sid !== 'string' ||
      req.headers.get('Authorization') !== null
    ) {
      return Response.json({ error: 'unauthorised' }, { status: 403 })
    }
    const raw = (await req.payload.db.findOne({
      collection: 'users',
      req,
      where: { id: { equals: req.user.id } },
    })) as { sessions?: { createdAt?: Date | string; id: string }[] } | null
    const sessions = raw?.sessions ?? []
    const session = sessions.find((s) => s.id === sid)
    if (!session) return Response.json({ error: 'no_session' }, { status: 404 })
    session.createdAt = new Date(Date.now() - SESSION_AGE_MS).toISOString()
    await req.payload.db.updateOne({
      collection: 'users',
      data: { sessions },
      id: req.user.id,
      req,
      returning: false,
    })
    return Response.json({ ok: true })
  },
  method: 'post',
  path: '/test/age-session',
}

const users: CollectionConfig = {
  slug: 'users',
  admin: { useAsTitle: 'name' },
  auth: { lockTime: 600_000, maxLoginAttempts: 5, useAPIKey: true },
  ...(process.env.PAYLOAD_E2E === 'true' ? { endpoints: [ageSessionEndpoint] } : {}),
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
  db = {},
  plugin = {},
  variant = 'single',
}: { db?: DatabaseOptions; plugin?: PasskeysPluginOptions; variant?: 'multi' | 'single' } = {}) =>
  buildConfig({
    admin: { importMap: { baseDir: path.resolve(dirname) }, user: 'users' },
    collections: variant === 'multi' ? [users, customers] : [users],
    // 127.0.0.1 stands in for a preview host: same app, not under the RP ID (Tasks 21 and 36).
    csrf: [SERVER_URL, 'http://127.0.0.1:3000'],
    db: databaseAdapter(db),
    email: testEmailAdapter,
    onInit: async (payload) => {
      if (process.env.NODE_ENV !== 'test') await seed(payload)
    },
    plugins: [
      passkeysPlugin({
        collections: variant === 'multi' ? ['users', 'customers'] : ['users'],
        onSignIn: (args) => testHooks.onSignIn?.(args as Record<string, unknown>) as undefined,
        ...plugin,
      }),
    ],
    secret: process.env.PAYLOAD_SECRET ?? 'dev-only-secret-change-me',
    serverURL: SERVER_URL,
    typescript: {
      // Payload spawns `payload generate:types` on every init outside production; under Vitest
      // that child outlives the run and spins, one per test file. The e2e dev server runs on
      // SQLite and would rewrite the committed (MongoDB) types with numeric IDs.
      autoGenerate: !process.env.VITEST && process.env.PAYLOAD_E2E !== 'true',
      // No `declare module 'payload'` block: the plugin's own source is type-checked in this
      // project and must compile against any host, not against this app's collection slugs.
      declare: false,
      outputFile: path.resolve(dirname, 'payload-types.ts'),
    },
  } satisfies Config)
