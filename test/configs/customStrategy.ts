import type { AuthStrategy } from '../../dev/buildConfig.js'

import { buildDevConfig } from '../../dev/buildConfig.js'

export const TEST_USER_HEADER = 'X-Test-User'

/**
 * A careless host strategy: any request with `X-Test-User: <email>` is that user, with the
 * user's newest session ID as `_sid` and no Authorization header. Every other check in
 * requireSignedIn passes for such a request, so only `_strategy !== 'local-jwt'` refuses it.
 */
const testHeaderStrategy: AuthStrategy = {
  authenticate: async ({ headers, payload }) => {
    const email = headers.get(TEST_USER_HEADER)
    if (!email) return { user: null }
    const raw = (await payload.db.findOne({
      collection: 'users',
      where: { email: { equals: email } },
    })) as ({ id: number | string; sessions?: { id: string }[] } & Record<string, unknown>) | null
    if (!raw) return { user: null }
    const doc = await payload.findByID({ collection: 'users', depth: 0, id: raw.id })
    return {
      user: {
        ...doc,
        _sid: raw.sessions?.at(-1)?.id,
        _strategy: 'test',
        collection: 'users',
      } as never,
    }
  },
  name: 'test-header',
}

// Its own file, so its own test fork: getPayload caches one instance per process.
export default buildDevConfig({
  authStrategies: [testHeaderStrategy],
  plugin: { limits: { anonymousChallenges: 50, passkeysPerUser: 3 } },
  variant: 'single',
})
