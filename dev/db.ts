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
  /**
   * Test only. `false` stands in for a host that builds no indexes (`ensureIndexes: false` and
   * Mongoose's `autoIndex: false`), to prove the plugin builds its own (design point 17).
   */
  mongoIndexes?: boolean
  /** Test only. Use this database name instead of the one in DATABASE_URL (MongoDB). */
  mongoDatabase?: string
}

const withDatabaseName = (url: string, name: string | undefined): string => {
  if (!name) return url
  const parsed = new URL(url)
  parsed.pathname = `/${name}`
  return parsed.toString()
}

export const databaseAdapter = ({ mongoDatabase, mongoIndexes = true }: DatabaseOptions = {}) => {
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
        migrationDir: path.resolve(dirname, 'migrations/postgres'),
        pool: {
          connectionString: url ?? 'postgres://postgres:postgres@127.0.0.1:5432/payload_passkeys',
        },
      })
    case 'sqlite':
      return sqliteAdapter({
        client: { url: url ?? `file:${path.resolve(dirname, 'dev.db')}` },
        migrationDir: path.resolve(dirname, 'migrations/sqlite'),
      })
  }
}
