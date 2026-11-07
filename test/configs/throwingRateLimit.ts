import type { RateLimitArgs } from '../../src/types.js'

import { buildDevConfig } from '../../dev/buildConfig.js'

/**
 * The single config with a rateLimit hook a test can swap. It needs its own file (and so its own
 * test fork): getPayload caches one instance per process, so a second config built inside another
 * spec would silently reuse the first instance's hook.
 */
export const limiter: {
  calls: Omit<RateLimitArgs, 'req'>[]
  impl: (args: RateLimitArgs) => unknown
} = {
  calls: [],
  impl: () => {
    throw new Error('limiter down')
  },
}

export default buildDevConfig({
  plugin: {
    limits: { anonymousChallenges: 50, passkeysPerUser: 3 },
    rateLimit: (args) => {
      const { req: _req, ...rest } = args
      limiter.calls.push(rest)
      return limiter.impl(args) as boolean
    },
  },
  variant: 'single',
})
