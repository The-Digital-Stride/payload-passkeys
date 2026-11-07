/**
 * Hosting domains in the private section of the Public Suffix List where every customer gets a
 * subdomain. Checked against publicsuffix.org's list on 2026-11-06. An RP ID equal to one of these
 * would let every other customer's site use the passkeys, and browsers refuse it anyway.
 */
export const HOSTING_PUBLIC_SUFFIXES: readonly string[] = [
  'amplifyapp.com',
  'azurestaticapps.net',
  'azurewebsites.net',
  'cloudfront.net',
  'deno.dev',
  'firebaseapp.com',
  'fly.dev',
  'github.io',
  'gitlab.io',
  'herokuapp.com',
  'netlify.app',
  'ngrok-free.app',
  'ngrok.app',
  'onrender.com',
  'pages.dev',
  'trycloudflare.com',
  'up.railway.app',
  'vercel.app',
  'vercel.dev',
  'web.app',
  'workers.dev',
]

export type RpIDProblem =
  | 'empty'
  | 'ip_address'
  | 'not_a_hostname'
  | 'not_lowercase'
  | 'public_suffix'
  | 'single_label'
  | 'trailing_dot'

const IPV4 = /^(\d{1,3})(\.\d{1,3}){3}$/
// Hex groups, colons and an optional dotted IPv4 tail; a colon is required.
const IPV6 = /^(?=.*:)[0-9a-f:.]+$/i

export const isIpAddress = (host: string): boolean => {
  const bare = host.replace(/^\[|\]$/g, '')
  return IPV4.test(bare) || IPV6.test(bare)
}

export const isHostingPublicSuffix = (host: string): boolean =>
  HOSTING_PUBLIC_SUFFIXES.includes(host)

/** Why a value can't be a WebAuthn RP ID, or null when it can. */
export const rpIDProblem = (rpID: string): null | RpIDProblem => {
  if (!rpID) return 'empty'
  if (isIpAddress(rpID)) return 'ip_address'
  if (!/^[a-zA-Z0-9.-]+$/.test(rpID)) return 'not_a_hostname'
  if (rpID !== rpID.toLowerCase()) return 'not_lowercase'
  if (rpID.endsWith('.')) return 'trailing_dot'
  if (!rpID.includes('.') && rpID !== 'localhost') return 'single_label'
  if (isHostingPublicSuffix(rpID)) return 'public_suffix'
  return null
}

const isLocalhost = (hostname: string): boolean =>
  hostname === 'localhost' || hostname.endsWith('.localhost')

/**
 * The origin (scheme, host, port) of a configured value, or null when it has a path, query or
 * fragment, isn't http(s), or is plain http anywhere but localhost (not a secure context).
 */
export const normaliseOrigin = (value: string): null | string => {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return null
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
  if (url.protocol === 'http:' && !isLocalhost(url.hostname)) return null
  if ((url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) return null
  if (url.username || url.password) return null
  return url.origin
}

/** True when the origin's host is the RP ID or a subdomain of it (WebAuthn L3 §5.1.4.1). */
export const originMatchesRpID = (origin: string, rpID: string): boolean => {
  let hostname: string
  try {
    hostname = new URL(origin).hostname
  } catch {
    return false
  }
  return hostname === rpID || hostname.endsWith(`.${rpID}`)
}
