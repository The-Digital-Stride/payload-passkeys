/**
 * Translation keys whose English mentions a password. Each has a neutral `…Sso` sibling that the
 * admin UI reads when `reauthentication` is 'sign-in-again'. No server code and no text here, so
 * the client can import it.
 */
export const SSO_KEYS = [
  'busy',
  'enrolBody',
  'removedSignOutUnconfirmed',
  'removeLast',
  'sectionDescription',
  'signInCancelled',
  'signInFailed',
  'signInUnavailableHere',
] as const

/** The translation key to read: the neutral `…Sso` sibling in 'sign-in-again' mode. */
export const keyForMode = (key: string, reauthentication: 'password' | 'sign-in-again'): string =>
  reauthentication === 'sign-in-again' && (SSO_KEYS as readonly string[]).includes(key)
    ? `${key}Sso`
    : key
