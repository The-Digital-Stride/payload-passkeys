import type { Browser, BrowserContext, Page } from '@playwright/test'

import { expect, test } from '@playwright/test'

import type { VirtualAuthenticator } from './helpers.js'

import {
  addVirtualAuthenticator,
  ageSession,
  ageSessionStatus,
  credentialsOf,
  DEV_USER,
  LOCALHOST,
  passwordSignIn,
  PREVIEW_HOST,
  signedInEmail,
  signOut,
} from './helpers.js'

// The cases build on each other and share one page, so the virtual authenticator keeps its
// credential from one case to the next. The copy is en.ts's, curly apostrophes included.
test.describe.configure({ mode: 'serial' })

let context: BrowserContext
let page: Page
let authenticator: VirtualAuthenticator

const toast = (text: string) =>
  page.getByRole('region', { name: /^Notifications/ }).getByText(text, { exact: true })

const passkeyRows = () => page.getByRole('listitem').filter({ hasText: /Added \d/ })

const signInWithPasskey = () => page.getByRole('button', { name: 'Sign in with a passkey' })

/** Adds a passkey from the account page, confirming the password if the session is not fresh. */
const addFromAccountPage = async () => {
  await page.getByRole('button', { name: 'Add a passkey' }).click()
  const passwordDialog = page.getByRole('dialog', { name: 'Confirm your password' })
  await expect(toast('Passkey added.').or(passwordDialog)).toBeVisible()
  if (await passwordDialog.isVisible()) {
    await passwordDialog.getByLabel('Password', { exact: true }).fill(DEV_USER.password)
    await passwordDialog.getByRole('button', { name: 'Confirm' }).click()
  }
  await expect(toast('Passkey added.')).toBeVisible()
}

const passkeySignIn = async () => {
  await expect(signInWithPasskey()).toBeVisible()
  await signInWithPasskey().click()
  await expect(page).not.toHaveURL(/\/admin\/login/)
}

test.beforeAll(async ({ browser }: { browser: Browser }) => {
  context = await browser.newContext()
  page = await context.newPage()
  authenticator = await addVirtualAuthenticator(page)
})

test.afterAll(async () => {
  await context.close()
})

test('1. a password sign-in offers a passkey, and adding one works', async () => {
  await passwordSignIn(page)
  const card = page.getByRole('dialog', { name: 'Sign in faster with a passkey' })
  await expect(card).toBeVisible()
  await expect(card).toContainText(
    'Next time, use your fingerprint, face or device PIN instead of your password.',
  )
  await card.getByRole('button', { name: 'Add a passkey' }).click()
  await expect(toast('Passkey added.')).toBeVisible()
  await expect(card).toBeHidden()

  const credentials = await credentialsOf(authenticator)
  expect(credentials).toHaveLength(1)
  expect(credentials[0]?.isResidentCredential).toBe(true)
})

test('2. the prompt does not come back in the same browser session', async () => {
  // A reload, as the plan asks. Case 6 checks it again once the account has no passkey left.
  await page.reload()
  await page.waitForLoadState('networkidle')
  await expect(page.getByRole('heading', { name: 'Collections' })).toBeVisible()
  await expect(page.getByRole('dialog', { name: 'Sign in faster with a passkey' })).toHaveCount(0)
})

test('3. signs in with the button', async () => {
  await signOut(page)
  await passkeySignIn()
  await expect(page).toHaveURL(`${LOCALHOST}/admin`)
  expect(await signedInEmail(page)).toBe(DEV_USER.email)

  // The account menu leads to the dev user's own document.
  await page.getByRole('banner').getByRole('link', { name: 'Account' }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'Dev' })).toBeVisible()
  await expect(page.getByRole('textbox', { name: 'Email' })).toHaveValue(DEV_USER.email)
})

test('4. redirects are kept to the admin', async () => {
  await signOut(page)
  await page.goto(`${LOCALHOST}/admin/login?redirect=%2Fadmin%2Fcollections%2Fusers`)
  await passkeySignIn()
  await expect(page).toHaveURL(/^http:\/\/localhost:3000\/admin\/collections\/users(\?.*)?$/)

  await signOut(page)
  await page.goto(`${LOCALHOST}/admin/login?redirect=https%3A%2F%2Fevil.test`)
  await passkeySignIn()
  await expect(page).toHaveURL(`${LOCALHOST}/admin`)
})

test('5. renames a passkey', async () => {
  await page.goto(`${LOCALHOST}/admin/account`)
  await expect(passkeyRows()).toHaveCount(1)
  await passkeyRows()
    .getByRole('button', { name: /^Rename: / })
    .click()
  const input = passkeyRows().getByRole('textbox', { name: 'Name' })
  await expect(input).toBeFocused()
  await input.fill('Work laptop')
  await input.press('Enter')
  await expect(toast('Passkey renamed.')).toBeVisible()

  await page.reload()
  await expect(passkeyRows()).toHaveCount(1)
  await expect(passkeyRows().first()).toContainText('Work laptop')
  await expect(page.getByRole('button', { name: 'Rename: Work laptop' })).toBeVisible()
})

test('6. removing a recently used passkey can sign out everywhere else', async ({ browser }) => {
  const other = await browser.newContext()
  try {
    const otherPage = await other.newPage()
    await passwordSignIn(otherPage)

    await page.getByRole('button', { name: 'Remove: Work laptop' }).click()
    const dialog = page
      .getByRole('dialog')
      .filter({ has: page.getByRole('heading', { name: 'Remove “Work laptop”?' }) })
    await expect(dialog).toBeVisible()
    await expect(dialog).toContainText(
      'This is your only passkey. You can still sign in with your password.',
    )
    // Used within 24 hours (the sign-in in case 4), so ticked by default (review M6).
    await expect(
      dialog.getByRole('checkbox', { name: 'Also sign out everywhere else' }),
    ).toBeChecked()
    await dialog.getByRole('button', { name: 'Remove', exact: true }).click()
    await expect(toast('Passkey removed.')).toBeVisible()
    await expect(page.getByText('You haven’t added a passkey yet.')).toBeVisible()

    await otherPage.goto(`${LOCALHOST}/admin`)
    await expect(otherPage).toHaveURL(/\/admin\/login/)

    await page.goto(`${LOCALHOST}/admin`)
    await expect(page).toHaveURL(`${LOCALHOST}/admin`)
    expect(await signedInEmail(page)).toBe(DEV_USER.email)
    // No passkey now, yet still no prompt: it is offered once per browser session (case 2).
    await page.waitForLoadState('networkidle')
    await expect(page.getByRole('dialog', { name: 'Sign in faster with a passkey' })).toHaveCount(0)
  } finally {
    await other.close()
  }
})

test('7. a failed ceremony shows the generic message', async () => {
  await page.goto(`${LOCALHOST}/admin/account`)
  await addFromAccountPage()
  await expect(passkeyRows()).toHaveCount(1)
  await signOut(page)

  const { authenticatorId, cdp } = authenticator
  await cdp.send('WebAuthn.setResponseOverrideBits', { authenticatorId, isBadUV: true })
  try {
    await signInWithPasskey().click()
    await expect(page.getByRole('alert').filter({ hasText: /passkey/ })).toHaveText(
      'That passkey couldn’t be used. Try again or sign in with your password.',
    )
    await expect(page).toHaveURL(/\/admin\/login/)
    expect(await signedInEmail(page)).toBeNull()
    // The dev-only endpoint case 9 uses refuses anyone not signed in.
    expect(await ageSessionStatus(page)).toBe(403)
  } finally {
    await cdp.send('WebAuthn.setResponseOverrideBits', {
      authenticatorId,
      isBadUP: false,
      isBadUV: false,
      isBogusSignature: false,
    })
  }
})

test('8. a preview host offers no passkeys', async () => {
  await page.goto(`${PREVIEW_HOST}/admin/login`)
  await expect(
    page.getByText('Passkey sign-in isn’t available at this address. Sign in with your password.'),
  ).toBeVisible()
  await expect(signInWithPasskey()).toHaveCount(0)

  // The dev config lists 127.0.0.1:3000 in `csrf`, so the password works here.
  await passwordSignIn(page, { origin: PREVIEW_HOST })
  await page.goto(`${PREVIEW_HOST}/admin/account`)
  await expect(page.getByText('Passkeys work on localhost only.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Add a passkey' })).toHaveCount(0)
})

test('9. an old session must confirm the password before adding a passkey', async () => {
  await passwordSignIn(page)
  await page.goto(`${LOCALHOST}/admin/account`)
  await expect(passkeyRows()).toHaveCount(1)
  await ageSession(page)
  // The authenticator already holds this account's passkey, which register/options excludes:
  // forget it, so the device can make a second one.
  await authenticator.cdp.send('WebAuthn.clearCredentials', {
    authenticatorId: authenticator.authenticatorId,
  })

  await page.getByRole('button', { name: 'Add a passkey' }).click()
  const dialog = page.getByRole('dialog', { name: 'Confirm your password' })
  await expect(dialog).toBeVisible()
  await expect(dialog).toContainText(
    'For your security, enter your password before adding a passkey.',
  )

  await dialog.getByLabel('Password', { exact: true }).fill('not-the-password')
  await dialog.getByRole('button', { name: 'Confirm' }).click()
  await expect(dialog.getByRole('alert')).toHaveText('That password didn’t work.')

  await dialog.getByLabel('Password', { exact: true }).fill(DEV_USER.password)
  await dialog.getByRole('button', { name: 'Confirm' }).click()
  await expect(toast('Passkey added.')).toBeVisible()
  await expect(dialog).toBeHidden()
  await expect(passkeyRows()).toHaveCount(2)
  expect(await signedInEmail(page)).toBe(DEV_USER.email)
})

test('10. with no passkey on the device, the button says how to add one', async () => {
  // A device that has never saved a passkey for this site, as a phone reached by QR code was
  // on the first try at ianhancock.com: the browser rejects with NotAllowedError, as it does
  // for a dismissed prompt, so the copy covers both.
  await authenticator.cdp.send('WebAuthn.clearCredentials', {
    authenticatorId: authenticator.authenticatorId,
  })
  await signOut(page)
  await signInWithPasskey().click()
  await expect(page.getByRole('alert').filter({ hasText: /passkey/i })).toHaveText(
    'No passkey was used. If you haven’t added one yet, sign in with your password, then add one from your account.',
  )
  await expect(page).toHaveURL(/\/admin\/login/)
  expect(await signedInEmail(page)).toBeNull()
  // The password still works.
  await passwordSignIn(page)
  expect(await signedInEmail(page)).toBe(DEV_USER.email)
})
