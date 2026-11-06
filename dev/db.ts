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

export const databaseAdapter = () => {
  const url = process.env.DATABASE_URL
  switch (adapterName()) {
    case 'mongo':
      // ensureIndexes: the unique index on passkey-challenge-uses is the replay guard (M3).
      return mongooseAdapter({
        ensureIndexes: true,
        url: url ?? 'mongodb://127.0.0.1/payload-passkeys',
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
