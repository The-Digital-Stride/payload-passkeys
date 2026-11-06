import type { Config } from 'payload'

import { describe, expect, it } from 'vitest'

import { passkeysPlugin } from '../../src/index.js'

const base = (overrides: Partial<Config> = {}): Config =>
  ({
    collections: [
      { slug: 'users', auth: true, fields: [] },
      { slug: 'customers', auth: true, fields: [] },
    ],
    secret: 'x',
    serverURL: 'https://example.com',
    ...overrides,
  }) as Config

const signIn = {
  clientProps: { collectionSlug: 'users' },
  path: '@the-digital-stride/payload-passkeys/client#SignInWithPasskey',
}

describe('admin components', () => {
  it('adds Sign in with a passkey after the login form, keeping the host’s components', () => {
    const config = passkeysPlugin()(
      base({ admin: { components: { afterLogin: ['/host#AfterLogin'] }, user: 'users' } }),
    )
    expect(config.admin?.components?.afterLogin).toEqual(['/host#AfterLogin', signIn])
  })

  it('uses the first auth collection when admin.user is unset', () => {
    expect(passkeysPlugin()(base()).admin?.components?.afterLogin).toEqual([signIn])
  })

  it('adds no sign-in button when the admin collection is not a passkeys collection', () => {
    const config = passkeysPlugin({ collections: ['customers'] })(
      base({ admin: { user: 'users' } }),
    )
    expect(config.admin?.components?.afterLogin).toEqual([])
  })

  it('adds nothing when disabled', () => {
    const config = passkeysPlugin({ enabled: false })(
      base({ admin: { components: { afterLogin: ['/host#AfterLogin'] } } }),
    )
    expect(config.admin?.components).toEqual({ afterLogin: ['/host#AfterLogin'] })
  })
})
