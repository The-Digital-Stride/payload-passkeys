import type { PayloadRequest } from 'payload'

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
   * From `x-real-ip`, else the first `x-forwarded-for` entry. Trustworthy only behind a proxy that
   * sets these headers itself (Vercel does); otherwise a client can choose its own value.
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
  passkey?: PublicPasskey
  req: PayloadRequest
  user: Record<string, unknown>
}

/**
 * Runs inside the sign-in transaction after the collection's beforeLogin hooks and before the token
 * is signed. Throw to refuse the sign-in; the new session is revoked. Exists because passkey
 * sign-in does not run the collection's beforeOperation/afterOperation hooks (review L8).
 */
export type OnSignInHook = (args: OnSignInArgs) => Promise<void> | void

export type PasskeysPluginOptions = {
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
  /** WebAuthn relying-party ID. Default: hostname of serverURL. */
  rpID?: string
  /** Shown by some passkey managers. Default: admin.meta.title, else the RP ID. */
  rpName?: string
  slugs?: { challengeUses?: string; challenges?: string; passkeys?: string }
}
