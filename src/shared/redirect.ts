import { getSafeRedirect } from 'payload/shared'

const normaliseAdminRoute = (adminRoute: string): string => {
  const trimmed = adminRoute.replace(/^\/+|\/+$/g, '')
  return trimmed ? `/${trimmed}` : '/'
}

/**
 * Where to go after a passkey sign-in. Payload's own getSafeRedirect rules out other origins and
 * the known tricks; on top of that the WHATWG parser resolves dot segments (including %2e%2e), and
 * the result must sit under the admin route, so the `redirect` parameter can't send a freshly
 * signed-in admin anywhere else on the site (review L5).
 */
export const safeAdminRedirect = (redirectTo: unknown, adminRoute = '/admin'): string => {
  const admin = normaliseAdminRoute(adminRoute)
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
  const inside = admin === '/' || pathname === admin || pathname.startsWith(`${admin}/`)
  return inside ? `${pathname}${search}${hash}` : admin
}
