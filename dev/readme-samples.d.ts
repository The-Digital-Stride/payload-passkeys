// Types for the README's rate-limit samples (dev/readme-samples.ts), so they type-check without
// installing the packages. Copied from the published declarations of @vercel/firewall 1.2.6 and
// @upstash/ratelimit 2.2.0, trimmed to what the samples use.

declare module '@vercel/firewall' {
  export function checkRateLimit(
    rateLimitId: string,
    options?: {
      firewallHostForDevelopment?: string
      headers?: Headers | Record<string, string> | Record<string, string | string[]>
      rateLimitKey?: string
      request?: Request
      timeout?: number
    },
  ): Promise<{ error?: 'blocked' | 'not-found'; rateLimited: boolean }>
}

declare module '@upstash/redis' {
  export class Redis {
    static fromEnv(): Redis
  }
}

declare module '@upstash/ratelimit' {
  import type { Redis } from '@upstash/redis'

  type Unit = 'd' | 'h' | 'm' | 'ms' | 's' | 'w'
  type Duration = `${number} ${Unit}` | `${number}${Unit}`
  type Algorithm = { readonly brand: 'upstash-ratelimit-algorithm' }

  export class Ratelimit {
    constructor(config: { limiter: Algorithm; prefix?: string; redis: Redis })
    static slidingWindow(tokens: number, window: Duration): Algorithm
    limit(
      identifier: string,
    ): Promise<{ limit: number; remaining: number; reset: number; success: boolean }>
  }
}
