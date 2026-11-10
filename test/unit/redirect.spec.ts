import { describe, expect, it } from 'vitest'

import { safeAdminRedirect } from '../../src/shared/redirect.js'

describe('safeAdminRedirect', () => {
  it.each([
    ['/admin', '/admin'],
    ['/admin/collections/posts?where=1#top', '/admin/collections/posts?where=1#top'],
    ['/admin/', '/admin/'],
  ])('keeps %s', (input, expected) => {
    expect(safeAdminRedirect(input, '/admin')).toBe(expected)
  })

  it.each([
    undefined,
    null,
    42,
    '',
    'https://evil.test/admin',
    '//evil.test/admin',
    '/\\evil.test',
    '/%2F%2Fevil.test',
    '/javascript:alert(1)',
    '/api/users/me',
    '/administrator',
    '/admin/../api/users',
    '/admin/%2e%2e/api/users',
    '/admin\n/x',
    ' /admin@evil.test',
  ])('sends %j to the admin root', (input) => {
    expect(safeAdminRedirect(input, '/admin')).toBe('/admin')
  })

  it('respects a custom admin route', () => {
    expect(safeAdminRedirect('/cms/collections/pages', '/cms')).toBe('/cms/collections/pages')
    expect(safeAdminRedirect('/admin', '/cms')).toBe('/cms')
    expect(safeAdminRedirect('/anything', '/')).toBe('/anything')
  })

  it('trims slashes from either end of the admin route', () => {
    expect(safeAdminRedirect('/cms/x', '//cms//')).toBe('/cms/x')
    expect(safeAdminRedirect('/cms/x', 'cms')).toBe('/cms/x')
    expect(safeAdminRedirect('/x', '///')).toBe('/x')
    expect(safeAdminRedirect('/x', '')).toBe('/x')
  })

  it('throws on an admin route that is not a string', () => {
    expect(() => safeAdminRedirect('/x', ['//evil.test'] as unknown as string)).toThrow(TypeError)
  })

  // CodeQL js/polynomial-redos: a backtracking trim took about 15 s on this admin route.
  it('trims an admin route holding a long run of slashes in linear time', () => {
    const adminRoute = `a${'/'.repeat(100_000)}a`
    const started = performance.now()
    expect(safeAdminRedirect('/admin', adminRoute)).toBe(`/${adminRoute}`)
    expect(performance.now() - started).toBeLessThan(500)
  })

  // getSafeRedirect refuses an encoded slash after the first; resolving dot segments can bring one
  // there (`/%2e/%2fevil.test` becomes `/%2fevil.test`), so the resolved path is checked again.
  it.each(['/%2fevil.test', '/%2e/%2fevil.test', '/./%2F%2Fevil.test', '/%2e/%2F%2Fevil.test'])(
    'sends %j to the admin root when the admin route is /',
    (input) => {
      expect(safeAdminRedirect(input, '/')).toBe('/')
    },
  )

  it.each([
    ['/.//evil.test', '/'],
    ['/admin/..//evil.test', ''],
    ['/./\\evil.test', '/'],
    ['/admin/.//evil.test', '/admin'],
  ])('never turns %j into a protocol-relative URL (admin route %j)', (input, adminRoute) => {
    const result = safeAdminRedirect(input, adminRoute)
    expect(result.startsWith('//')).toBe(false)
    expect(result.startsWith('/\\')).toBe(false)
  })
})

// D2: an encoded slash, backslash or dot left in the resolved path. No admin path needs one, and a
// server that decodes it later could resolve somewhere else.
describe('safeAdminRedirect: encoded characters in the path', () => {
  it.each([
    '/admin/a%2fb',
    '/admin/a%2Fb',
    '/admin/a%5cb',
    '/admin/a%5Cb',
    '/admin/a%2eb',
    '/admin/a%2Eb',
    '/admin/collections/%2e%2e%2e',
    '/admin/%2F/x',
  ])('sends %j to the admin root', (input) => {
    expect(safeAdminRedirect(input, '/admin')).toBe('/admin')
  })

  it('refuses them under a root admin route too', () => {
    expect(safeAdminRedirect('/a%2Fb', '/')).toBe('/')
    expect(safeAdminRedirect('/a%5cb', '/')).toBe('/')
  })

  it('keeps an encoded slash in the query string (Payload qs-encodes the redirect it builds)', () => {
    const input = '/admin/collections/posts?where%5Bslug%5D=%2Fnews%2F&redirect=%2Fadmin%2Fx'
    expect(safeAdminRedirect(input, '/admin')).toBe(input)
  })

  it('keeps an encoded slash in the hash', () => {
    expect(safeAdminRedirect('/admin/x#a%2Fb', '/admin')).toBe('/admin/x#a%2Fb')
  })

  it('does not decode twice: a double-encoded dot segment passes unchanged', () => {
    expect(safeAdminRedirect('/admin/%252e%252e/api', '/admin')).toBe('/admin/%252e%252e/api')
  })
})

describe('safeAdminRedirect: maxLength', () => {
  const pathOf = (length: number) => `/admin/${'a'.repeat(length - '/admin/'.length)}`

  it('has no cap by default: a 3,000-character admin path passes', () => {
    const input = pathOf(3_000)
    expect(input).toHaveLength(3_000)
    expect(safeAdminRedirect(input, '/admin')).toBe(input)
  })

  it('passes a valid path of exactly maxLength', () => {
    const input = pathOf(1_500)
    expect(safeAdminRedirect(input, '/admin', { maxLength: 1_500 })).toBe(input)
  })

  it('refuses an input one character over maxLength', () => {
    const input = pathOf(1_501)
    expect(safeAdminRedirect(input, '/admin', { maxLength: 1_500 })).toBe('/admin')
  })

  it('keeps the hash and counts it', () => {
    const path = pathOf(1_400)
    const kept = `${path}#${'h'.repeat(99)}`
    expect(kept).toHaveLength(1_500)
    expect(safeAdminRedirect(kept, '/admin', { maxLength: 1_500 })).toBe(kept)
    expect(safeAdminRedirect(`${kept}h`, '/admin', { maxLength: 1_500 })).toBe('/admin')
  })

  it('counts the result as percent-encoded, so non-ASCII paths reach the cap sooner', () => {
    const input = `/admin/${'é'.repeat(600)}`
    expect(input.length).toBeLessThan(1_500)
    expect(safeAdminRedirect(input, '/admin', { maxLength: 1_500 })).toBe('/admin')
    expect(safeAdminRedirect(input, '/admin')).toBe(`/admin/${'%C3%A9'.repeat(600)}`)
  })

  it('counts a long input that resolves to something short', () => {
    const input = `/admin/${'x/../'.repeat(400)}ok`
    expect(input.length).toBeGreaterThan(1_500)
    expect(safeAdminRedirect(input, '/admin')).toBe('/admin/ok')
    expect(safeAdminRedirect(input, '/admin', { maxLength: 1_500 })).toBe('/admin')
  })
})
