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

describe('the Passkeys section field', () => {
  const fieldsOf = (config: Config, slug: string) =>
    (config.collections ?? []).find((c) => c.slug === slug)?.fields ?? []

  it('adds a ui field to each passkeys collection, rendered by the RSC wrapper', () => {
    const config = passkeysPlugin({ collections: ['users'] })(base())
    expect(fieldsOf(config, 'users')).toContainEqual({
      name: 'passkeysManager',
      type: 'ui',
      admin: {
        components: {
          Field: {
            clientProps: { collectionSlug: 'users' },
            path: '@the-digital-stride/payload-passkeys/rsc#PasskeysManagerField',
          },
        },
        disableListColumn: true,
      },
    })
    expect(fieldsOf(config, 'customers').map((f) => ('name' in f ? f.name : null))).toEqual([])
  })

  it('leaves it out when disabled, keeping the user handle', () => {
    const names = fieldsOf(passkeysPlugin({ enabled: false })(base()), 'users').map((f) =>
      'name' in f ? f.name : null,
    )
    expect(names).toEqual(['passkeyUserHandle'])
  })
})

describe('the passkeys provider', () => {
  const provider = (enrolmentPrompt: boolean, collections = ['users']) => ({
    clientProps: { collections, enrolmentPrompt },
    path: '@the-digital-stride/payload-passkeys/client#PasskeysProvider',
  })

  it('wraps the admin after the host’s own providers', () => {
    const config = passkeysPlugin()(
      base({ admin: { components: { providers: ['/host#Provider'] }, user: 'users' } }),
    )
    expect(config.admin?.components?.providers).toEqual(['/host#Provider', provider(true)])
  })

  it('passes the collections and the enrolment prompt option', () => {
    const config = passkeysPlugin({ collections: ['users', 'customers'], enrolmentPrompt: false })(
      base(),
    )
    expect(config.admin?.components?.providers).toEqual([provider(false, ['users', 'customers'])])
  })

  it('is left out when disabled', () => {
    expect(passkeysPlugin({ enabled: false })(base()).admin?.components?.providers).toBeUndefined()
  })
})
