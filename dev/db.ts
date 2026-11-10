import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { postgresAdapter } from '@payloadcms/db-postgres'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import path from 'path'
import { fileURLToPath } from 'url'

const dirname = path.dirname(fileURLToPath(import.meta.url))

export type AdapterName = 'mongo' | 'postgres' | 'sqlite'

export const adapterName = (): AdapterName => {
  const value = process.env.DATABASE_ADAPTER ?? 'mongo'
  if (value === 'mongo' || value === 'postgres' || value === 'sqlite') return value
  throw new Error(`DATABASE_ADAPTER must be mongo, postgres or sqlite, not "${value}"`)
}

export type DatabaseOptions = {
  /** Test only. Store blocks as JSON on the main table (Postgres and SQLite `blocksAsJSON`). */
  blocksAsJSON?: boolean
  /**
   * Test only. `false` stands in for a host that builds no indexes (`ensureIndexes: false` and
   * Mongoose's `autoIndex: false`), to prove the plugin builds its own (design point 17).
   */
  mongoIndexes?: boolean
  /** Test only. Use this database name instead of the one in DATABASE_URL (MongoDB). */
  mongoDatabase?: string
  /** Test only. The most connections the Postgres pool may open (pg's `max`; its default is 10). */
  postgresPoolMax?: number
  /**
   * Test only. Run SQLite in transactions (`transactionOptions: {}`). Off by default, as in
   * @payloadcms/db-sqlite, which then runs none.
   */
  sqliteTransactions?: boolean
}

const withDatabaseName = (url: string, name: string | undefined): string => {
  if (!name) return url
  const parsed = new URL(url)
  parsed.pathname = `/${name}`
  return parsed.toString()
}

export const databaseAdapter = ({
  blocksAsJSON,
  mongoDatabase,
  mongoIndexes = true,
  postgresPoolMax,
  sqliteTransactions,
}: DatabaseOptions = {}) => {
  const url = process.env.DATABASE_URL
  switch (adapterName()) {
    case 'mongo':
      // ensureIndexes: the unique index on passkey-challenge-uses is the replay guard (M3).
      return mongooseAdapter({
        ...(mongoIndexes
          ? { ensureIndexes: true }
          : { connectOptions: { autoIndex: false }, ensureIndexes: false }),
        url: withDatabaseName(url ?? 'mongodb://127.0.0.1/payload-passkeys', mongoDatabase),
      })
    case 'postgres':
      return postgresAdapter({
        ...(blocksAsJSON ? { blocksAsJSON } : {}),
        migrationDir: path.resolve(dirname, 'migrations/postgres'),
        pool: {
          connectionString: url ?? 'postgres://postgres:postgres@127.0.0.1:5432/payload_passkeys',
          ...(postgresPoolMax ? { max: postgresPoolMax } : {}),
        },
      })
    case 'sqlite':
      return sqliteAdapter({
        ...(blocksAsJSON ? { blocksAsJSON } : {}),
        client: { url: url ?? `file:${path.resolve(dirname, 'dev.db')}` },
        migrationDir: path.resolve(dirname, 'migrations/sqlite'),
        ...(sqliteTransactions ? { transactionOptions: {} } : {}),
      })
  }
}
