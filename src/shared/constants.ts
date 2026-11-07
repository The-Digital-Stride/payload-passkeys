export const PACKAGE_NAME = '@the-digital-stride/payload-passkeys'

export const DEFAULT_SLUGS = {
  challengeUses: 'passkey-challenge-uses',
  challenges: 'passkey-challenges',
  passkeys: 'passkeys',
} as const

export const USER_HANDLE_FIELD = 'passkeyUserHandle'
export const MANAGER_FIELD = 'passkeysManager'

export const CHALLENGE_TTL_MS = 5 * 60 * 1000
export const CEREMONY_TIMEOUT_MS = 5 * 60 * 1000
export const MAX_PASSKEY_NAME = 64
/** EdDSA, ES256, RS256 (WebAuthn L3 §5.4). */
export const SUPPORTED_ALGORITHM_IDS = [-8, -7, -257]

export const ENDPOINTS = {
  delete: '/passkeys/delete',
  reauth: '/passkeys/reauth',
  registerOptions: '/passkeys/register/options',
  registerVerify: '/passkeys/register/verify',
  rename: '/passkeys/rename',
  signInOptions: '/passkeys/sign-in/options',
  signInVerify: '/passkeys/sign-in/verify',
  status: '/passkeys/status',
} as const

/** Error codes the endpoints return as { error }. The client maps each to copy. */
export type PasskeysErrorCode =
  | 'bad_request'
  | 'busy'
  | 'forbidden_origin'
  | 'not_found'
  | 'rate_limited'
  | 'reauth_failed'
  | 'reauth_required'
  | 'registration_failed'
  | 'retry'
  | 'server_error'
  | 'sign_in_failed'
  | 'too_many_passkeys'
  | 'unauthorised'
  | 'unavailable'
  | 'unsupported_media_type'
