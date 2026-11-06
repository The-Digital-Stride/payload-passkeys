/**
 * Every code sample in README.md, type-checked by `pnpm typecheck` (dev/tsconfig.json includes
 * dev/**). test/unit/readmeSamples.spec.ts checks that each region between `// readme:<name>` and
 * `// readme:end` appears verbatim in README.md, so the README can't drift from code that compiles.
 * Nothing imports this file. `@vercel/firewall` and `@upstash/*` are not installed: their types are
 * stubbed in dev/readme-samples.d.ts, referenced below because tsc skips a .d.ts that shares its
 * name with an included .ts file.
 */
// eslint-disable-next-line @typescript-eslint/triple-slash-reference -- the stubs are ambient
/// <reference path="./readme-samples.d.ts" />
import type { Config } from 'payload'

// readme:minimal
import { passkeysPlugin } from '@the-digital-stride/payload-passkeys'

export const plugins: Config['plugins'] = [passkeysPlugin()]
// readme:end

// readme:options
export const configured = passkeysPlugin({
  collections: ['users'],
  enabled: true,
  enrolmentPrompt: true,
  freshSessionMinutes: 10,
  limits: { anonymousChallenges: 500, passkeysPerUser: 20 },
  logging: { ip: 'truncated' },
  origins: ['https://example.com', 'https://www.example.com'],
  rpID: 'example.com',
  rpName: 'Example admin',
  slugs: {
    challengeUses: 'passkey-challenge-uses',
    challenges: 'passkey-challenges',
    passkeys: 'passkeys',
  },
})
// readme:end

// readme:csrf
const serverURL = process.env.NEXT_PUBLIC_SERVER_URL ?? 'http://localhost:3000'

export const csrf: Config['csrf'] = [
  serverURL,
  ...(process.env.VERCEL_URL ? [`https://${process.env.VERCEL_URL}`] : []),
  ...(process.env.VERCEL_BRANCH_URL ? [`https://${process.env.VERCEL_BRANCH_URL}`] : []),
]
// readme:end

// readme:vercel
import type { RateLimitHook } from '@the-digital-stride/payload-passkeys'
import { checkRateLimit } from '@vercel/firewall'

export const vercelRateLimit: RateLimitHook = async ({ key, req }) => {
  // The firewall exists only on Vercel; allow everything in local development.
  if (process.env.VERCEL !== '1') return true
  const { error, rateLimited } = await checkRateLimit('passkeys', {
    headers: req.headers,
    rateLimitKey: key,
  })
  // error 'not-found' means no rule has the ID "passkeys": refuse rather than run unlimited.
  return !rateLimited && !error
}
// readme:end

// readme:upstash
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const limiter = new Ratelimit({
  limiter: Ratelimit.slidingWindow(10, '1 m'),
  prefix: 'passkeys',
  redis: Redis.fromEnv(),
})

export const upstashRateLimit: RateLimitHook = async ({ action, key }) =>
  (await limiter.limit(`${action}:${key}`)).success
// readme:end

// readme:on-sign-in
export const withAudit = passkeysPlugin({
  // Runs inside the sign-in transaction, after the beforeLogin hooks. Throw to refuse.
  onSignIn: ({ collection, passkey, req, user }) => {
    req.payload.logger.info({
      collection,
      credentialIdPrefix: passkey?.credentialId.slice(0, 8),
      event: 'audit.admin_signed_in',
      method: 'passkey',
      msg: 'audit.admin_signed_in',
      userId: user.id,
    })
  },
})
// readme:end

// readme:translations
export const i18n: Config['i18n'] = {
  translations: {
    en: { passkeys: { signInWithPasskey: 'Use a passkey' } },
  },
}
// readme:end
