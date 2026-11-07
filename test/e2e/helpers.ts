import type { CDPSession, Page } from '@playwright/test'

import { expect } from '@playwright/test'

import { devUser } from '../../dev/helpers/credentials.js'

export const LOCALHOST = 'http://localhost:3000'
/** Same app, not under the RP ID `localhost`: stands in for a preview deployment (design §5). */
export const PREVIEW_HOST = 'http://127.0.0.1:3000'

export const DEV_USER = { email: devUser.email, password: devUser.password }

export type VirtualAuthenticator = { authenticatorId: string; cdp: CDPSession }

/** A platform authenticator with UV, as Touch ID or Windows Hello would be (Verified facts Q6). */
export const addVirtualAuthenticator = async (page: Page): Promise<VirtualAuthenticator> => {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      automaticPresenceSimulation: true,
      defaultBackupEligibility: true,
      defaultBackupState: true,
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      protocol: 'ctap2',
      transport: 'internal',
    },
  })
  return { authenticatorId, cdp }
}

/** The fields of CDP's `WebAuthn.Credential` these tests read. */
export type VirtualCredential = { credentialId: string; isResidentCredential: boolean }

export const credentialsOf = async ({
  authenticatorId,
  cdp,
}: VirtualAuthenticator): Promise<VirtualCredential[]> =>
  (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials

export const passwordSignIn = async (
  page: Page,
  { origin = LOCALHOST, password = DEV_USER.password, path = '/admin/login' } = {},
) => {
  await page.goto(`${origin}${path}`)
  await page.getByLabel('Email').fill(DEV_USER.email)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Login' }).click()
  await expect(page).not.toHaveURL(/\/admin\/login/)
}

export const signOut = async (page: Page, origin = LOCALHOST) => {
  await page.goto(`${origin}/admin/logout`)
  await expect(page).toHaveURL(/\/admin\/login/)
}

/** The signed-in user's email as /me reports it on that origin, or null when signed out. */
export const signedInEmail = async (page: Page): Promise<null | string> =>
  page.evaluate(async () => {
    const res = await fetch('/api/users/me', { credentials: 'include' })
    const body = (await res.json()) as { user?: { email?: string } | null }
    return body.user?.email ?? null
  })

/**
 * Calls the dev-only endpoint (dev/buildConfig.ts, PAYLOAD_E2E) that moves this page's own session
 * 30 minutes back, from the page, so the request carries the session cookie and the Origin
 * header Payload's CSRF check wants.
 */
export const ageSessionStatus = async (page: Page): Promise<number> =>
  page.evaluate(async () => {
    const res = await fetch('/api/users/test/age-session', {
      credentials: 'include',
      method: 'POST',
    })
    return res.status
  })

export const ageSession = async (page: Page) => {
  expect(await ageSessionStatus(page)).toBe(200)
}
