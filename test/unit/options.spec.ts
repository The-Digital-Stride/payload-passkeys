import type { Config } from 'payload'

import { describe, expect, it } from 'vitest'

import { PasskeysConfigError, resolveOptions } from '../../src/server/options.js'

const base = (overrides: Partial<Config> = {}): Config =>
  ({
    collections: [{ slug: 'users', auth: true, fields: [] }],
    secret: 'x',
    serverURL: 'https://example.com',
    ...overrides,
  }) as Config

describe('resolveOptions defaults', () => {
  it('derives everything from serverURL and admin.user', () => {
    const resolved = resolveOptions(base(), {})
    expect(resolved).toMatchObject({
      collections: ['users'],
      enabled: true,
      enrolmentPrompt: true,
      freshSessionMs: 600_000,
      limits: { anonymousChallenges: 500, passkeysPerUser: 20 },
      logging: { ip: 'truncated' },
      origins: ['https://example.com'],
      rateLimitIsDefault: true,
      rpID: 'example.com',
      rpName: 'example.com',
      secureCookies: true,
      slugs: {
        challengeUses: 'passkey-challenge-uses',
        challenges: 'passkey-challenges',
        passkeys: 'passkeys',
      },
    })
  })

  it('uses admin.user, then the first auth collection', () => {
    const config = base({
      admin: { user: 'admins' },
      collections: [
        { slug: 'users', auth: true, fields: [] },
        { slug: 'admins', auth: true, fields: [] },
      ],
    })
    expect(resolveOptions(config, {}).collections).toEqual(['admins'])
  })

  it('takes rpName from admin.meta.title', () => {
    expect(resolveOptions(base({ admin: { meta: { title: 'Site admin' } } }), {}).rpName).toBe(
      'Site admin',
    )
  })

  it('reads a title template object', () => {
    const title = { default: 'Site admin', template: '%s | Site' }
    expect(resolveOptions(base({ admin: { meta: { title } } }), {}).rpName).toBe('Site admin')
  })

  it('uses plain cookie names on http://localhost', () => {
    const resolved = resolveOptions(base({ serverURL: 'http://localhost:3000' }), {})
    expect(resolved).toMatchObject({
      origins: ['http://localhost:3000'],
      rpID: 'localhost',
      secureCookies: false,
    })
  })

  it('accepts several origins under the RP ID', () => {
    const resolved = resolveOptions(base(), {
      origins: ['https://example.com', 'https://www.example.com/'],
      rpID: 'example.com',
    })
    expect(resolved.origins).toEqual(['https://example.com', 'https://www.example.com'])
  })
})

describe('resolveOptions refuses impossible configs', () => {
  const refuses = (
    config: Config,
    options: Parameters<typeof resolveOptions>[1],
    message: RegExp,
  ) => {
    expect(() => resolveOptions(config, options)).toThrow(PasskeysConfigError)
    expect(() => resolveOptions(config, options)).toThrow(message)
  }

  it('no RP ID and no serverURL', () => refuses(base({ serverURL: undefined }), {}, /rpID/))
  it('a hosting public suffix', () =>
    refuses(base(), { origins: ['https://vercel.app'], rpID: 'vercel.app' }, /public suffix/))
  it('an origin outside the RP ID', () =>
    refuses(
      base(),
      { origins: ['https://example.com', 'https://preview.vercel.app'], rpID: 'example.com' },
      /preview\.vercel\.app/,
    ))
  it('an origin with a path', () =>
    refuses(base(), { origins: ['https://example.com/admin'] }, /origin/))
  it('plain http off localhost', () =>
    refuses(base({ serverURL: 'http://example.com' }), {}, /origin/))
  it('an unknown collection', () => refuses(base(), { collections: ['members'] }, /members/))
  it('a collection without auth', () =>
    refuses(
      base({
        collections: [
          { slug: 'users', auth: true, fields: [] },
          { slug: 'posts', fields: [] },
        ],
      }),
      { collections: ['posts'] },
      /auth/,
    ))
  it('useSessions: false (review H4)', () =>
    refuses(
      base({ collections: [{ slug: 'users', auth: { useSessions: false }, fields: [] }] }),
      {},
      /useSessions/,
    ))
  it('disableLocalStrategy', () =>
    refuses(
      base({ collections: [{ slug: 'users', auth: { disableLocalStrategy: true }, fields: [] }] }),
      {},
      /disableLocalStrategy/,
    ))
  it('endpoints: false', () =>
    refuses(
      base({ collections: [{ slug: 'users', auth: true, endpoints: false, fields: [] }] }),
      {},
      /endpoints/,
    ))
  it("sameSite 'None' with no csrf list (review M4)", () =>
    refuses(
      base({
        collections: [
          { slug: 'users', auth: { cookies: { sameSite: 'None', secure: true } }, fields: [] },
        ],
        serverURL: undefined,
      }),
      { rpID: 'example.com', origins: ['https://example.com'] },
      /csrf/,
    ))
  it('a slug that already exists', () =>
    refuses(
      base({
        collections: [
          { slug: 'users', auth: true, fields: [] },
          { slug: 'passkeys', fields: [] },
        ],
      }),
      {},
      /passkeys/,
    ))
  it('limits that are not positive whole numbers', () =>
    refuses(base(), { limits: { passkeysPerUser: 0 } }, /passkeysPerUser/))
  it('freshSessionMinutes out of range', () =>
    refuses(base(), { freshSessionMinutes: 0 }, /freshSessionMinutes/))
})

describe('resolveOptions warnings', () => {
  it('warns when csrf will be empty', () => {
    const resolved = resolveOptions(base({ serverURL: undefined }), {
      origins: ['https://example.com'],
      rpID: 'example.com',
    })
    expect(resolved.warnings.join('\n')).toMatch(/csrf/)
  })
  it('does not warn about csrf when serverURL is set', () => {
    expect(resolveOptions(base(), {}).warnings.join('\n')).not.toMatch(/csrf/)
  })
})
