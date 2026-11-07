import type { MongooseAdapter } from '@payloadcms/db-mongodb'
import type { Config, Payload } from 'payload'

import { randomBytes } from 'crypto'
import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

import { buildDevConfig } from '../../dev/buildConfig.js'
import { passkeysPlugin } from '../../src/index.js'
import { bootPasskeys } from '../../src/server/boot.js'
import { RECHECK_INTERVAL_MS } from '../../src/server/health.js'
import { getPasskeysOptions } from '../../src/server/context.js'
import type { TestClient } from '../helpers/api.js'

import config from '../configs/single.js'
import { createClient } from '../helpers/api.js'
import { createUser, PASSWORD } from '../helpers/users.js'

const isMongo = (process.env.DATABASE_ADAPTER ?? 'mongo') === 'mongo'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const indexesOf = async (instance: Payload, slug: string) =>
  (instance.db as unknown as MongooseAdapter).collections[slug]!.collection.indexes()

const uniqueIndexOn = async (instance: Payload, slug: string, field: string) =>
  (await indexesOf(instance, slug)).find((index) => index.key[field] === 1 && index.unique)

describe('bootPasskeys', () => {
  it('logs the resolved RP ID and origins', async () => {
    const info = vi.spyOn(payload.logger, 'info')
    await bootPasskeys(payload, getPasskeysOptions(payload))
    expect(info).toHaveBeenCalledWith(
      expect.objectContaining({ origins: ['http://localhost:3000'], rpID: 'localhost' }),
    )
    info.mockRestore()
  })

  it('warns in production when rateLimit is left at its default (review M2)', async () => {
    const warn = vi.spyOn(payload.logger, 'warn')
    vi.stubEnv('NODE_ENV', 'production')
    try {
      await bootPasskeys(payload, getPasskeysOptions(payload))
    } finally {
      vi.unstubAllEnvs()
    }
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ msg: expect.stringMatching(/rateLimit/) }),
    )
    warn.mockRestore()
  })

  it('does not warn about rateLimit outside production', async () => {
    const warn = vi.spyOn(payload.logger, 'warn')
    await bootPasskeys(payload, getPasskeysOptions(payload))
    expect(warn).not.toHaveBeenCalledWith(
      expect.objectContaining({ msg: expect.stringMatching(/rateLimit/) }),
    )
    warn.mockRestore()
  })

  it.runIf(isMongo)(
    'rebuilds the unique index replay protection depends on (review M3)',
    async () => {
      const model = (payload.db as unknown as MongooseAdapter).collections[
        'passkey-challenge-uses'
      ]!
      await model.collection.dropIndexes()
      expect(await uniqueIndexOn(payload, 'passkey-challenge-uses', 'challenge')).toBeUndefined()
      await bootPasskeys(payload, getPasskeysOptions(payload))
      expect(await uniqueIndexOn(payload, 'passkey-challenge-uses', 'challenge')).toBeDefined()
    },
  )
})

// A host with ensureIndexes: false and Mongoose's autoIndex: false builds no indexes at all, so
// without the plugin's own boot step a challenge could be consumed twice (design point 17).
describe.runIf(isMongo)('on MongoDB with the host building no indexes', () => {
  let bare: Payload
  const bareConfig = buildDevConfig({
    db: {
      mongoDatabase: `payload-passkeys-noindex-${randomBytes(4).toString('hex')}`,
      mongoIndexes: false,
    },
    plugin: { limits: { anonymousChallenges: 50, passkeysPerUser: 3 } },
  })
  beforeAll(async () => {
    bare = await getPayload({ config: bareConfig, key: 'no-indexes' })
  })
  afterAll(async () => {
    await bare?.db.connection?.dropDatabase()
    await bare?.destroy()
  })

  it('has the unique indexes by the time getPayload resolves', async () => {
    expect(await uniqueIndexOn(bare, 'passkey-challenge-uses', 'challenge')).toMatchObject({
      name: 'challenge_1',
    })
    expect(await uniqueIndexOn(bare, 'passkey-challenges', 'challenge')).toMatchObject({
      name: 'challenge_1',
    })
    expect(await uniqueIndexOn(bare, 'passkeys', 'credentialId')).toMatchObject({
      name: 'credentialId_1',
    })
  })

  it('refuses a second use of the same challenge', async () => {
    const data = {
      challenge: randomBytes(32).toString('base64url'),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    }
    await bare.db.create({ collection: 'passkey-challenge-uses', data })
    await expect(bare.db.create({ collection: 'passkey-challenge-uses', data })).rejects.toThrow()
    expect(
      (
        await bare.db.count({
          collection: 'passkey-challenge-uses',
          where: { challenge: { equals: data.challenge } },
        })
      ).totalDocs,
    ).toBe(1)
  })

  it('turns passkey ceremonies off when it cannot build a unique index, and back on', async () => {
    const model = (bare.db as unknown as MongooseAdapter).collections['passkey-challenge-uses']!
    const user = await createUser(bare, 'users')
    const anonymous = createClient(bareConfig, { payloadKey: 'no-indexes' })
    const owner = createClient(bareConfig, { payloadKey: 'no-indexes' })
    const ceremonies = [
      '/sign-in/options',
      '/sign-in/verify',
      '/register/options',
      '/register/verify',
    ]
    const call = (client: TestClient, path: string) =>
      client.post(`/api/users/passkeys${path}`, { response: {} })

    await model.collection.dropIndexes()
    const doc = { challenge: 'duplicate', expiresAt: new Date() }
    await model.collection.insertMany([{ ...doc }, { ...doc }])
    const error = vi.spyOn(bare.logger, 'error')
    try {
      await bootPasskeys(bare, getPasskeysOptions(bare))
      expect(error).toHaveBeenCalledWith(
        expect.objectContaining({
          msg: expect.stringMatching(
            /unique index on passkey-challenge-uses\.challenge is missing/,
          ),
        }),
      )
      // Password sign-in still works.
      const login = await owner.post('/api/users/login', { email: user.email, password: PASSWORD })
      expect(login.status).toBe(200)
      for (const path of ceremonies) {
        const res = await call(path.startsWith('/register') ? owner : anonymous, path)
        expect([path, res.status, res.json]).toEqual([path, 503, { error: 'unavailable' }])
      }
      expect((await anonymous.post('/api/users/passkeys/status')).json).toEqual({
        available: false,
      })
      expect((await owner.post('/api/users/passkeys/status')).json).toMatchObject({
        available: false,
        reason: 'indexes',
      })
    } finally {
      error.mockRestore()
      await model.collection.deleteMany({ challenge: 'duplicate' })
    }

    // With the cause gone and no restart, a request re-checks once the interval has passed (a
    // first deploy's cold starts met a dropped Atlas connection and stayed off until restarted).
    expect((await call(anonymous, '/sign-in/options')).status).toBe(503)
    vi.useFakeTimers({ now: Date.now() + RECHECK_INTERVAL_MS, toFake: ['Date'] })
    try {
      expect((await owner.post('/api/users/passkeys/status')).json).toMatchObject({
        available: true,
      })
      expect(await uniqueIndexOn(bare, 'passkey-challenge-uses', 'challenge')).toBeDefined()
      expect((await call(anonymous, '/sign-in/options')).status).toBe(200)
    } finally {
      vi.useRealTimers()
    }

    // A healthy boot keeps them on.
    await bootPasskeys(bare, getPasskeysOptions(bare))
    expect(await uniqueIndexOn(bare, 'passkey-challenge-uses', 'challenge')).toBeDefined()
    expect((await call(anonymous, '/sign-in/options')).status).toBe(200)
    expect((await call(owner, '/register/options')).status).toBe(200)
    expect((await owner.post('/api/users/passkeys/status')).json).toMatchObject({
      available: true,
    })
  })
})

describe('onInit', () => {
  const host = (calls: string[]): Config =>
    ({
      collections: [{ slug: 'users', auth: true, fields: [] }],
      onInit: () => {
        calls.push('host')
      },
      secret: 'x',
      serverURL: 'https://example.com',
    }) as unknown as Config

  it.each([true, false])(
    'runs the boot checks, then the host onInit, when enabled is %s',
    async (enabled) => {
      const calls: string[] = []
      const logger = { error: vi.fn(), info: vi.fn(() => calls.push('boot')), warn: vi.fn() }
      await passkeysPlugin({ enabled })(host(calls)).onInit!({
        db: { name: 'sqlite' },
        logger,
      } as unknown as Payload)
      expect(calls).toEqual(['boot', 'host'])
    },
  )
})
