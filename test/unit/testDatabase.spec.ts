import { describe, expect, it } from 'vitest'

import { DEFAULT_TEST_POSTGRES_URL, resolveTestDatabase } from '../helpers/testDatabase.js'

// `pnpm test:int` drops the database it runs against (PAYLOAD_DROP_DATABASE), so it must never
// run against one it inherited from dev/.env or the shell.
describe('resolveTestDatabase', () => {
  it('defaults to MongoDB in memory', () => {
    expect(resolveTestDatabase({})).toEqual({ adapter: 'mongo', source: 'memory-server' })
  })

  it.each([
    ['mongo', { adapter: 'mongo', source: 'memory-server' }],
    ['sqlite', { adapter: 'sqlite', source: 'temp-file' }],
    ['postgres', { adapter: 'postgres', source: 'url', url: DEFAULT_TEST_POSTGRES_URL }],
  ])('uses its own database for %s', (adapter, expected) => {
    expect(resolveTestDatabase({ DATABASE_ADAPTER: adapter })).toEqual(expected)
  })

  it.each([
    ['mongo', 'mongodb://127.0.0.1/payload-passkeys'],
    ['mongo', 'mongodb+srv://user:pass@cluster0.example.net/production'],
    ['sqlite', 'file:/Users/someone/site/payload.db'],
    ['postgres', 'postgres://user:pass@db.example.com:5432/production'],
    ['postgres', 'postgres://postgres:postgres@127.0.0.1:5432/another_project'],
  ])('ignores an inherited DATABASE_URL (%s, %s)', (adapter, url) => {
    const resolved = resolveTestDatabase({ DATABASE_ADAPTER: adapter, DATABASE_URL: url })
    expect(JSON.stringify(resolved)).not.toContain(url)
  })

  it.each([
    'postgres://postgres:postgres@127.0.0.1:5432/payload_passkeys_ci',
    'postgresql://postgres@localhost/payload_passkeys',
  ])('accepts a local PAYLOAD_TEST_DATABASE_URL for postgres: %s', (url) => {
    expect(
      resolveTestDatabase({
        DATABASE_ADAPTER: 'postgres',
        DATABASE_URL: 'postgres://user@db.example.com/production',
        PAYLOAD_TEST_DATABASE_URL: url,
      }),
    ).toEqual({ adapter: 'postgres', source: 'url', url })
  })

  it.each([
    'postgres://user:pass@db.example.com:5432/production',
    'postgres://user@10.0.0.5/payload',
    'postgres://user@[::1]/payload',
    'postgres://user@localhost.example.com/payload',
    'postgres://user@localhost/payload?host=db.example.com',
    'postgres://user@localhost/payload?hostaddr=10.0.0.5',
    'postgres:///payload?host=/var/run/postgresql',
    'mysql://root@127.0.0.1/payload',
    'not a url',
  ])('refuses a PAYLOAD_TEST_DATABASE_URL that is not local postgres: %s', (url) => {
    expect(() =>
      resolveTestDatabase({ DATABASE_ADAPTER: 'postgres', PAYLOAD_TEST_DATABASE_URL: url }),
    ).toThrow(/PAYLOAD_TEST_DATABASE_URL/)
  })

  it('ignores PAYLOAD_TEST_DATABASE_URL for mongo and sqlite', () => {
    const env = { PAYLOAD_TEST_DATABASE_URL: 'postgres://postgres@127.0.0.1/x' }
    expect(resolveTestDatabase({ ...env, DATABASE_ADAPTER: 'mongo' })).toEqual({
      adapter: 'mongo',
      source: 'memory-server',
    })
    expect(resolveTestDatabase({ ...env, DATABASE_ADAPTER: 'sqlite' })).toEqual({
      adapter: 'sqlite',
      source: 'temp-file',
    })
  })

  it('refuses an unknown adapter', () => {
    expect(() => resolveTestDatabase({ DATABASE_ADAPTER: 'mysql' })).toThrow(/DATABASE_ADAPTER/)
  })
})
