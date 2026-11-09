import { safeAdminRedirect } from '../../shared/redirect.js'

/**
 * Whether a failed logout means the session is still there. Payload answers 400 ("No User"), 401
 * or 403 when there is no session to end (another tab signed it out, a reset, token expiry): that
 * is as good as signed out, so go on to the login page. A network failure (0) or a 5xx may have
 * left the session alive, and bouncing then would only return to the admin.
 */
export const sessionMayRemain = (status: number): boolean =>
  status !== 200 && ![400, 401, 403].includes(status)

/**
 * Where the "sign in again" button sends the browser: the admin login route, with `redirect` set
 * to the page the admin is on. The redirect goes through safeAdminRedirect, so it can only point
 * back inside the admin.
 */
export const signInAgainUrl = ({
  adminRoute,
  current,
  loginRoute = '/login',
}: {
  adminRoute: string
  current: string
  loginRoute?: string
}): string => {
  const admin = adminRoute.replace(/\/+$/, '')
  const login = loginRoute.startsWith('/') ? loginRoute : `/${loginRoute}`
  const redirect = safeAdminRedirect(current, adminRoute)
  return `${admin}${login}?redirect=${encodeURIComponent(redirect)}`
}
