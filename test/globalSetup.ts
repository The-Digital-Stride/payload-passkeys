import { mkdirSync, rmSync } from 'fs'
import { MongoMemoryReplSet } from 'mongodb-memory-server'
import path from 'path'

import { resolveTestDatabase } from './helpers/testDatabase.js'

// The int project drops the database it runs against (PAYLOAD_DROP_DATABASE), so this always
// overwrites DATABASE_URL, whatever dev/.env or the shell set it to (test/helpers/testDatabase.ts).
export default async function setup(): Promise<() => Promise<void>> {
  let database: ReturnType<typeof resolveTestDatabase>
  try {
    database = resolveTestDatabase(process.env)
  } catch (error) {
    // Vitest 5 fails to print a globalSetup error (its stack mapper throws), so say it here.
    console.error(`\n${error instanceof Error ? error.message : String(error)}\n`)
    throw error
  }

  if (database.adapter === 'mongo') {
    const replSet = await MongoMemoryReplSet.create({
      replSet: { count: 1, storageEngine: 'wiredTiger' },
    })
    process.env.DATABASE_URL = replSet.getUri('payload-passkeys-test')
    return async () => {
      await replSet.stop()
    }
  }

  if (database.adapter === 'sqlite') {
    const dir = path.resolve('test/.tmp')
    mkdirSync(dir, { recursive: true })
    const file = path.join(dir, `int-${process.pid}.db`)
    process.env.DATABASE_URL = `file:${file}`
    return async () => {
      rmSync(file, { force: true })
    }
  }

  process.env.DATABASE_URL = database.url
  return async () => {}
}
