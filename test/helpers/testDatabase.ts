// Which database `pnpm test:int` runs against. The int project sets PAYLOAD_DROP_DATABASE, so
// whatever this picks is dropped at boot: it must never be a database the suite inherited, from
// dev/.env (vitest.config.ts loads it) or from the shell. So DATABASE_URL is never read here.

export type TestDatabase =
  | { adapter: 'mongo'; source: 'memory-server' }
  | { adapter: 'postgres'; source: 'url'; url: string }
  | { adapter: 'sqlite'; source: 'temp-file' }

/**
 * A database of its own on the Postgres dev/docker-compose.yml runs, never the dev app's
 * `payload_passkeys` (dev/db.ts), which the suite would drop. Payload's Postgres adapter creates it
 * on first connect. CI sets PAYLOAD_TEST_DATABASE_URL to its service's database instead.
 */
export const DEFAULT_TEST_POSTGRES_URL =
  'postgres://postgres:postgres@127.0.0.1:5432/payload_passkeys_test'

const LOCAL_HOSTS = new Set(['127.0.0.1', 'localhost'])

/**
 * Throws unless `url` is a postgres URL on this machine. A `host` or `hostaddr` query parameter
 * is refused too: pg reads it in place of the host in the URL.
 */
export const assertLocalPostgresUrl = (url: string, variable: string): void => {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    throw new Error(`${variable} is not a valid URL.`)
  }
  const refuse = (why: string) =>
    new Error(
      `${variable} must be a postgres URL on 127.0.0.1 or localhost (${why}). The suite drops the ` +
        'database it runs against, so it refuses anything else.',
    )
  if (parsed.protocol !== 'postgres:' && parsed.protocol !== 'postgresql:') {
    throw refuse(`scheme ${parsed.protocol}`)
  }
  if (!LOCAL_HOSTS.has(parsed.hostname)) throw refuse(`host "${parsed.hostname}"`)
  for (const key of parsed.searchParams.keys()) {
    if (key === 'host' || key === 'hostaddr') throw refuse(`a ${key} parameter`)
  }
}

export const resolveTestDatabase = (env: Record<string, string | undefined>): TestDatabase => {
  const adapter = env.DATABASE_ADAPTER || 'mongo'
  switch (adapter) {
    case 'mongo':
      return { adapter, source: 'memory-server' }
    case 'postgres': {
      const explicit = env.PAYLOAD_TEST_DATABASE_URL
      if (!explicit) return { adapter, source: 'url', url: DEFAULT_TEST_POSTGRES_URL }
      assertLocalPostgresUrl(explicit, 'PAYLOAD_TEST_DATABASE_URL')
      return { adapter, source: 'url', url: explicit }
    }
    case 'sqlite':
      return { adapter, source: 'temp-file' }
    default:
      throw new Error(`DATABASE_ADAPTER must be mongo, postgres or sqlite, not "${adapter}"`)
  }
}
