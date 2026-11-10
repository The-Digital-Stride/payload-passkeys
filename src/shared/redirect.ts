import { getSafeRedirect } from 'payload/shared'

const normaliseAdminRoute = (adminRoute: string): string => {
  const trimmed = adminRoute.replace(/^\/+|\/+$/g, '')
  return trimmed ? `/${trimmed}` : '/'
}

/** An encoded slash, backslash or dot: no admin path needs one (design D2). */
const ENCODED_SEPARATOR = /%(?:2f|5c|2e)/i

export type SafeAdminRedirectOptions = {
  /**
   * Longest input, and longest result, to accept; anything longer returns the admin route. No cap
   * by default. The input is counted as given and the result as percent-encoded (so a non-ASCII
   * path counts each character as up to 12), and the `#hash` counts. Pass one when the path is
   * carried somewhere with a size limit, such as an OAuth state cookie (`{ maxLength: 1500 }`).
   */
  maxLength?: number
}

/**
 * Where to go after a sign-in: a same-origin path under the admin route, or the admin route
 * itself. Payload's own getSafeRedirect rules out other origins and the known tricks; on top of
 * that the WHATWG parser resolves dot segments (including %2e%2e), and the result must sit under
 * the admin route, so the `redirect` parameter can't send a freshly signed-in admin anywhere else
 * on the site (review L5). A resolved path that still holds `%2f`, `%5c` or `%2e` (any case) is
 * refused: a server that decodes it later could resolve elsewhere. The query string and hash may
 * hold them. It decodes once, as the URL parser does: `%252e` is left as it is.
 *
 * Pure and safe on the client and the server. Returns the admin route for anything it refuses,
 * including a non-string.
 */
export const safeAdminRedirect = (
  redirectTo: unknown,
  adminRoute = '/admin',
  options: SafeAdminRedirectOptions = {},
): string => {
  const admin = normaliseAdminRoute(adminRoute)
  const { maxLength } = options
  const tooLong = (value: string) => maxLength !== undefined && value.length > maxLength
  if (typeof redirectTo === 'string' && tooLong(redirectTo)) return admin
  const safe = getSafeRedirect({
    fallbackTo: admin,
    redirectTo: typeof redirectTo === 'string' ? redirectTo : '',
  })
  if (safe === admin) return admin
  let url: URL
  try {
    url = new URL(safe, 'http://localhost')
  } catch {
    return admin
  }
  if (url.origin !== 'http://localhost' || url.username || url.password) return admin
  const { hash, pathname, search } = url
  // Resolving dot segments can leave `//host` (`/.//evil.test`), which a browser reads as another
  // origin. getSafeRedirect only refuses that before resolution, so check again after it.
  if (/^\/[/\\]/.test(pathname)) return admin
  if (ENCODED_SEPARATOR.test(pathname)) return admin
  const inside = admin === '/' || pathname === admin || pathname.startsWith(`${admin}/`)
  if (!inside) return admin
  // Resolution can also bring something getSafeRedirect refuses to the front (`/%2e/%2fevil.test`
  // becomes `/%2fevil.test`), so the resolved result must pass it again, unchanged.
  const resolved = `${pathname}${search}${hash}`
  if (tooLong(resolved)) return admin
  return getSafeRedirect({ fallbackTo: admin, redirectTo: resolved }) === resolved
    ? resolved
    : admin
}
