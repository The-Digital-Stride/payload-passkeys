import type { Payload, PayloadRequest } from 'payload'

import type { PasskeysTranslationKey } from './translations/en.js'

export type PasskeyAction =
  | 'delete'
  | 'reauth'
  | 'register.options'
  | 'register.verify'
  | 'rename'
  | 'sign-in.options'
  | 'sign-in.verify'
  | 'status'

export type RateLimitArgs = {
  action: PasskeyAction
  collection: string
  /**
   * The rightmost `x-forwarded-for` entry (the one the nearest proxy appended), or what the
   * `clientIp` option returns; null when that isn't an IP address. Trustworthy only when the
   * nearest proxy appends or sets that header itself; otherwise a client can choose its own value.
   */
  ip: null | string
  /** `<collection>:<userId>` for signed-in calls, `ip:<ip>` for anonymous ones. */
  key: string
  req: PayloadRequest
  userId?: number | string
}

/** Return true to allow the request. A throw or anything but true refuses it with 429. */
export type RateLimitHook = (args: RateLimitArgs) => boolean | Promise<boolean>

export type DeviceType = 'multiDevice' | 'singleDevice'

/** What the plugin ever sends to a browser about a passkey. No public key, no counter. */
export type PublicPasskey = {
  aaguid: null | string
  backedUp: boolean
  createdAt: string
  credentialId: string
  deviceType: DeviceType
  id: number | string
  lastUsedAt: null | string
  name: string
  rpID: string
  transports: string[]
}

export type OnSignInArgs = {
  collection: string
  /** 'passkey' for a passkey sign-in; 'sso' for signInVerifiedUser (a host's own SSO callback). */
  method: 'passkey' | 'sso'
  /** The passkey used. Set only when `method` is 'passkey'. */
  passkey?: PublicPasskey
  req: PayloadRequest
  /**
   * A copy of the stored user after the beforeLogin hooks, without Payload's internal fields
   * (`hash`, `salt`, `sessions`, `apiKey`, `apiKeyIndex`, the reset and verification tokens,
   * `loginAttempts`, `lockUntil`, `passkeyUserHandle`). Changing it changes nothing.
   */
  user: Record<string, unknown>
}

/**
 * Runs inside the sign-in transaction after the collection's beforeLogin hooks and before the token
 * is signed. Throw to refuse the sign-in; the new session is revoked. Exists because passkey
 * sign-in does not run the collection's beforeOperation/afterOperation hooks (review L8).
 */
export type OnSignInHook = (args: OnSignInArgs) => Promise<void> | void

/**
 * How an admin whose sign-in is older than `freshSessionMinutes` proves it's them before adding a
 * passkey. 'password': re-enter the password (the default). 'sign-in-again': sign out and sign in
 * again, for admins who sign in with SSO and have no password they know. In that mode the `reauth`
 * endpoint is not registered.
 */
export type Reauthentication = 'password' | 'sign-in-again'

export type PasskeysPluginOptions = {
  /**
   * The caller's IP, for `rateLimit` and failure logs. Default: the rightmost `x-forwarded-for`
   * entry. Set it when that isn't your client, for example `(req) => req.headers.get('x-real-ip')`
   * behind nginx with `proxy_set_header X-Real-IP $remote_addr`. Non-IP values become null.
   */
  clientIp?: (req: PayloadRequest) => null | string | undefined
  /** Auth collections that get passkeys. Default: [admin.user] (or the first auth collection). */
  collections?: string[]
  /** false keeps the schema (fields and collections) but adds no endpoints or admin components. */
  enabled?: boolean
  /** Offer "Sign in faster with a passkey" after a password sign-in. Default true. */
  enrolmentPrompt?: boolean
  /** How recent a sign-in must be to add a passkey without re-entering the password. Default 10. */
  freshSessionMinutes?: number
  limits?: {
    /** Outstanding anonymous sign-in challenges across the site, then 429. Default 500. */
    anonymousChallenges?: number
    /** Passkeys per user. Default 20. */
    passkeysPerUser?: number
  }
  /** IP addresses in failure logs. Default 'truncated' (/24, /48). Never logged on success. */
  logging?: { ip?: 'full' | 'none' | 'truncated' }
  onSignIn?: OnSignInHook
  /** Exact origins (scheme, host, port) the admin is served from. Default: [serverURL origin]. */
  origins?: string[]
  rateLimit?: RateLimitHook
  /**
   * How an admin proves it's them when their sign-in is older than freshSessionMinutes.
   * Default 'password'. Use 'sign-in-again' when admins sign in with SSO.
   */
  reauthentication?: Reauthentication
  /** WebAuthn relying-party ID. Default: hostname of serverURL. */
  rpID?: string
  /** Shown by some passkey managers. Default: admin.meta.title, else the RP ID. */
  rpName?: string
  slugs?: { challengeUses?: string; challenges?: string; passkeys?: string }
}

export type SignInVerifiedUserArgs = {
  /** The auth collection's slug. Must be one of the plugin's `collections`. */
  collection: string
  /**
   * The incoming request's headers, so beforeLogin hooks, onSignIn and IP logging see the real
   * request. Optional, but pass them: without them those see empty headers.
   */
  headers?: Headers
  payload: Payload
  /** The id of a user the caller has already verified (for example in an OAuth callback). */
  userId: number | string
}

export type SignInVerifiedUserResult = {
  /** When the token expires, in seconds since the epoch. */
  exp: number
  /** A complete Set-Cookie header value for Payload's auth cookie. */
  setCookie: string
  /** The user as /me returns it, without hash, salt, sessions or other secrets. */
  user: Record<string, unknown>
}

/**
 * Overrides for the plugin's admin text, by key: the `passkeys` namespace of one language in
 * Payload's `i18n.translations`, for example `{ en: { passkeys: overrides } }`.
 */
export type PasskeysTranslations = Partial<Record<PasskeysTranslationKey, string>>

/**
 * refuseSignInUnless's predicate. It receives the user's stored record without `hash`, `salt`,
 * `sessions` or the plugin's other secret fields, with `collection` (the auth collection's slug)
 * added: the raw record, so depth 0, no afterRead hooks and no virtual fields. Return true to
 * allow the sign-in; anything else, or a throw, refuses it.
 */
export type SignInAllowed = (user: Record<string, unknown>) => boolean | Promise<boolean>

export type RefuseSignInUnlessOptions = {
  /**
   * How long the re-read of the stored user may take, in milliseconds, before the sign-in is
   * refused. Default 5000. On Postgres the re-read needs a second pool connection.
   */
  recheckTimeoutMs?: number
}
