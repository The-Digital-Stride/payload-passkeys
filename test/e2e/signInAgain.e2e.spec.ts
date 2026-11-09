import type { BrowserContext, Page } from '@playwright/test'

import { expect, test } from '@playwright/test'

import {
  addVirtualAuthenticator,
  ageSession,
  DEV_USER,
  passwordSignIn,
  signedInEmail,
} from './helpers.js'

// Runs against the second dev app (playwright.config.ts, 'sign-in-again' project): the plugin with
// reauthentication: 'sign-in-again', as an SSO site would have it. Copy is en.ts's.
const ORIGIN = 'http://localhost:3001'

let context: BrowserContext
let page: Page

test.beforeAll(async ({ browser }) => {
  context = await browser.newContext()
  page = await context.newPage()
  await addVirtualAuthenticator(page)
})

test.afterAll(async () => {
  await context.close()
})

test('a stale session is sent to sign in again, with no password field', async () => {
  await passwordSignIn(page, { origin: ORIGIN })
  await page.goto(`${ORIGIN}/admin/account`)
  // SSO wording: nothing here mentions a password.
  await expect(page.getByText('Your usual sign-in still works.')).toBeVisible()
  await ageSession(page)

  await page.getByRole('button', { name: 'Add a passkey' }).click()
  const dialog = page.getByRole('dialog', { name: 'Sign in again first' })
  await expect(dialog).toBeVisible()
  await expect(dialog).toContainText(
    'For your security, you can only add a passkey shortly after signing in. Sign in again, then add it straight away.',
  )
  await expect(dialog.locator('input')).toHaveCount(0)
  await expect(page.getByRole('dialog', { name: 'Confirm your password' })).toHaveCount(0)

  // Cancel leaves the session alone.
  await dialog.getByRole('button', { name: 'Cancel' }).click()
  await expect(dialog).toBeHidden()
  expect(await signedInEmail(page)).not.toBeNull()

  await page.getByRole('button', { name: 'Add a passkey' }).click()
  await dialog.getByRole('button', { name: 'Sign in again' }).click()
  await expect(page).toHaveURL(/\/admin\/login\?redirect=/)
  expect(new URL(page.url()).searchParams.get('redirect')).toBe('/admin/account')
  expect(await signedInEmail(page)).toBeNull()
})

test('after signing in again the passkey can be added straight away', async () => {
  await page.getByLabel('Email').fill(DEV_USER.email)
  await page.getByLabel('Password').fill(DEV_USER.password)
  await page.getByRole('button', { name: 'Login' }).click()
  await expect(page).toHaveURL(/\/admin\/account/)
  await page.getByRole('button', { name: 'Add a passkey' }).click()
  await expect(
    page
      .getByRole('region', { name: /^Notifications/ })
      .getByText('Passkey added.', { exact: true }),
  ).toBeVisible()
})
