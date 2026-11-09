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
  onSignIn: ({ collection, method, passkey, req, user }) => {
    req.payload.logger.info({
      collection,
      credentialIdPrefix: passkey?.credentialId.slice(0, 8),
      event: 'audit.admin_signed_in',
      method, // 'passkey', or 'sso' when the sign-in came from signInVerifiedUser
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

// readme:sso-option
export const forSsoAdmins = passkeysPlugin({ reauthentication: 'sign-in-again' })
// readme:end

// Stands for the host's own OAuth code: it checks `state` and the provider's response, then finds
// (or creates) the user. Outside the README regions on purpose.
declare const verifyGoogleCallback: (
  request: Request,
) => Promise<{ redirectTo: string; userId: number | string }>

// readme:sso-callback
// app/api/auth/google/callback/route.ts
import { signInVerifiedUser } from '@the-digital-stride/payload-passkeys'
import { getPayload } from 'payload'
import config from '@payload-config'
import { NextResponse } from 'next/server.js'

export const GET = async (request: Request) => {
  // Check the OAuth `state` and the provider's response FIRST. signInVerifiedUser signs in as
  // whoever you name, so call it only after those checks have passed.
  // `redirectTo` is the login page's `redirect`, carried through the OAuth `state`.
  const { redirectTo, userId } = await verifyGoogleCallback(request)

  const payload = await getPayload({ config })
  const { setCookie } = await signInVerifiedUser({
    collection: 'users',
    headers: request.headers, // so beforeLogin, onSignIn and IP logging see the real request
    payload,
    userId,
  })
  const response = NextResponse.redirect(
    new URL(/^\/admin(?:[/?#]|$)/.test(redirectTo) ? redirectTo : '/admin', request.url),
  )
  // Delete or set any other cookies through response.cookies BEFORE appending: Next rewrites the
  // whole Set-Cookie header from its own cookie map whenever response.cookies changes.
  response.cookies.delete('oauth_state')
  response.headers.append('Set-Cookie', setCookie)
  return response
}
// readme:end

// readme:sso-offboarding
import type { CollectionAfterChangeHook, CollectionBeforeLoginHook } from 'payload'
import { UnauthorizedError } from 'payload'
import { resetPasskeys } from '@the-digital-stride/payload-passkeys'

// Refuse disabled users on every sign-in: SSO and passkeys both run beforeLogin.
export const refuseDisabled: CollectionBeforeLoginHook = ({ req, user }) => {
  if (user.disabled) throw new UnauthorizedError(req.t)
  return user
}

// And clean up when someone is disabled.
export const cleanUpOnDisable: CollectionAfterChangeHook = async ({ doc, previousDoc, req }) => {
  if (doc.disabled && !previousDoc.disabled) {
    await resetPasskeys({ collection: 'users', id: doc.id, payload: req.payload, req })
  }
}
// readme:end

// readme:sso-wording
import type { PasskeysTranslations } from '@the-digital-stride/payload-passkeys'

const ssoWording: PasskeysTranslations = {
  enrolBodySso: 'Next time, use your fingerprint, face or device PIN instead of Google.',
}

export const ssoI18n: Config['i18n'] = {
  translations: { en: { passkeys: ssoWording } },
}
// readme:end
