import type { CollectionConfig, Config, IncomingAuthType, PayloadRequest } from 'payload'

import type { OnSignInHook, PasskeysPluginOptions, RateLimitHook } from '../types.js'

import { DEFAULT_SLUGS } from '../shared/constants.js'
import { normaliseOrigin, originMatchesRpID, rpIDProblem } from '../shared/rpid.js'
import { clientIp } from './ip.js'

export class PasskeysConfigError extends Error {
  constructor(message: string) {
    super(`[payload-passkeys] ${message}`)
    this.name = 'PasskeysConfigError'
  }
}

export type ResolvedOptions = {
  /** The caller's IP, or null when it isn't one (clientIp in ip.ts, with the host's resolver). */
  clientIp: (req: PayloadRequest) => null | string
  collections: string[]
  enabled: boolean
  enrolmentPrompt: boolean
  freshSessionMs: number
  limits: { anonymousChallenges: number; passkeysPerUser: number }
  logging: { ip: 'full' | 'none' | 'truncated' }
  onSignIn?: OnSignInHook
  origins: string[]
  rateLimit: RateLimitHook
  rateLimitIsDefault: boolean
  rpID: string
  rpName: string
  /** `__Host-` and `Secure` on the browser-key cookies, from the configured origins (review L7). */
  secureCookies: boolean
  slugs: { challengeUses: string; challenges: string; passkeys: string }
  /** Logged once at boot (Task 25); config time has no logger. */
  warnings: string[]
}

export const allowEverything: RateLimitHook = () => true

const authOf = (collection: CollectionConfig): IncomingAuthType | null => {
  if (!collection.auth) return null
  return collection.auth === true ? {} : collection.auth
}

const positiveInteger = (value: unknown, name: string, fallback: number): number => {
  if (value === undefined) return fallback
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw new PasskeysConfigError(
      `${name} must be a whole number of at least 1, not ${String(value)}.`,
    )
  }
  return value
}

type MetaTitle = NonNullable<NonNullable<Config['admin']>['meta']>['title']

/** admin.meta.title is a string or a Next.js title template object. */
const titleText = (title: MetaTitle): string | undefined => {
  if (!title) return undefined
  if (typeof title === 'string') return title
  return 'absolute' in title ? title.absolute : title.default
}

const serverURLOrigin = (serverURL: string | undefined): null | string => {
  if (!serverURL) return null
  try {
    return normaliseOrigin(new URL(serverURL).origin)
  } catch {
    return null
  }
}

export const resolveOptions = (config: Config, options: PasskeysPluginOptions): ResolvedOptions => {
  const all = config.collections ?? []
  const warnings: string[] = []

  // Collections
  const firstAuth = all.find((collection) => collection.auth)?.slug
  const collections =
    options.collections ?? [config.admin?.user ?? firstAuth].filter((s): s is string => !!s)
  if (collections.length === 0) {
    throw new PasskeysConfigError(
      'No auth collection found. Pass `collections` or add an auth collection.',
    )
  }
  for (const slug of collections) {
    const collection = all.find((c) => c.slug === slug)
    if (!collection) throw new PasskeysConfigError(`Collection "${slug}" is not in the config.`)
    const auth = authOf(collection)
    if (!auth)
      throw new PasskeysConfigError(
        `Collection "${slug}" has no auth. Passkeys need an auth collection.`,
      )
    if (auth.disableLocalStrategy) {
      throw new PasskeysConfigError(
        `Collection "${slug}" sets auth.disableLocalStrategy. Passkeys mint Payload's own JWT sessions, so the local strategy must be on.`,
      )
    }
    if (auth.useSessions === false) {
      throw new PasskeysConfigError(
        `Collection "${slug}" sets auth.useSessions: false. Passkeys need server-side sessions so that sign-out and revocation work.`,
      )
    }
    if (collection.endpoints === false) {
      throw new PasskeysConfigError(
        `Collection "${slug}" sets endpoints: false, so it cannot host the passkey endpoints.`,
      )
    }
  }

  // RP ID and origins (review M9)
  const fromServerURL = serverURLOrigin(config.serverURL)
  if (config.serverURL && !fromServerURL && !options.origins) {
    throw new PasskeysConfigError(
      `serverURL "${config.serverURL}" is not a usable origin (https, or http on localhost). Pass \`origins\`.`,
    )
  }
  const rawOrigins = options.origins ?? (fromServerURL ? [fromServerURL] : [])
  const origins = rawOrigins.map((value) => {
    const origin = normaliseOrigin(value)
    if (!origin) {
      throw new PasskeysConfigError(
        `"${value}" is not a valid origin: use scheme, host and optional port only, https except on localhost.`,
      )
    }
    return origin
  })
  const rpID = options.rpID ?? (origins[0] ? new URL(origins[0]).hostname : undefined)
  if (!rpID) {
    throw new PasskeysConfigError(
      'Set `rpID` and `origins`, or set serverURL, so the plugin knows which domain passkeys belong to.',
    )
  }
  if (origins.length === 0) throw new PasskeysConfigError('Set `origins` (serverURL is not set).')
  const problem = rpIDProblem(rpID)
  if (problem === 'public_suffix') {
    throw new PasskeysConfigError(
      `rpID "${rpID}" is a hosting public suffix; every other site on it could use your passkeys. Use your own domain.`,
    )
  }
  if (problem) throw new PasskeysConfigError(`rpID "${rpID}" is not a valid RP ID (${problem}).`)
  for (const origin of origins) {
    if (!originMatchesRpID(origin, rpID)) {
      throw new PasskeysConfigError(
        `Origin ${origin} is not ${rpID} or a subdomain of it, so passkeys for ${rpID} can't work there.`,
      )
    }
  }
  const secureCookies = origins.every((origin) => origin.startsWith('https:'))

  // CSRF (review M4). Sanitize appends serverURL to csrf, so csrf is empty only when both are.
  const csrfWillBeEmpty = (config.csrf?.length ?? 0) === 0 && !config.serverURL
  if (csrfWillBeEmpty) {
    const sameSiteNone = collections.some((slug) => {
      const auth = authOf(all.find((c) => c.slug === slug)!)
      return auth?.cookies?.sameSite === 'None'
    })
    if (sameSiteNone) {
      throw new PasskeysConfigError(
        "auth.cookies.sameSite is 'None' and the csrf list is empty, so any site could use the session cookie. Set `csrf` to your origins.",
      )
    }
    warnings.push(
      `The csrf list is empty, so Payload accepts the session cookie from any origin. Set \`csrf: ${JSON.stringify(origins)}\` in your Payload config.`,
    )
  }

  // Slugs
  const slugs = { ...DEFAULT_SLUGS, ...options.slugs }
  for (const slug of Object.values(slugs)) {
    if (all.some((c) => c.slug === slug)) {
      throw new PasskeysConfigError(
        `A collection called "${slug}" already exists. Pass \`slugs\` to rename the plugin's collections.`,
      )
    }
  }
  if (new Set(Object.values(slugs)).size !== 3)
    throw new PasskeysConfigError('The three slugs must differ.')

  // Numbers
  const freshSessionMinutes = positiveInteger(
    options.freshSessionMinutes,
    'freshSessionMinutes',
    10,
  )
  if (freshSessionMinutes > 60)
    throw new PasskeysConfigError('freshSessionMinutes must be 60 or less.')
  const limits = {
    anonymousChallenges: positiveInteger(
      options.limits?.anonymousChallenges,
      'limits.anonymousChallenges',
      500,
    ),
    passkeysPerUser: positiveInteger(options.limits?.passkeysPerUser, 'limits.passkeysPerUser', 20),
  }
  const ip = options.logging?.ip ?? 'truncated'
  if (!['full', 'none', 'truncated'].includes(ip))
    throw new PasskeysConfigError(`logging.ip must be 'none', 'truncated' or 'full'.`)

  if (options.clientIp !== undefined && typeof options.clientIp !== 'function')
    throw new PasskeysConfigError('clientIp must be a function of the request.')

  return {
    clientIp: (req) => clientIp(req, options.clientIp),
    collections,
    enabled: options.enabled ?? true,
    enrolmentPrompt: options.enrolmentPrompt ?? true,
    freshSessionMs: freshSessionMinutes * 60_000,
    limits,
    logging: { ip },
    onSignIn: options.onSignIn,
    origins,
    rateLimit: options.rateLimit ?? allowEverything,
    rateLimitIsDefault: !options.rateLimit,
    rpID,
    rpName: options.rpName || titleText(config.admin?.meta?.title) || rpID,
    secureCookies,
    slugs,
    warnings,
  }
}
