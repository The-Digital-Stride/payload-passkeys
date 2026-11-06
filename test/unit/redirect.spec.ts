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
