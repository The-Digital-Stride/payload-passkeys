import { mkdirSync, rmSync } from 'fs'
import { MongoMemoryReplSet } from 'mongodb-memory-server'
import path from 'path'

export default async function setup(): Promise<() => Promise<void>> {
  const adapter = process.env.DATABASE_ADAPTER ?? 'mongo'

  if (adapter === 'mongo' && !process.env.DATABASE_URL) {
    const replSet = await MongoMemoryReplSet.create({
      replSet: { count: 1, storageEngine: 'wiredTiger' },
    })
    process.env.DATABASE_URL = replSet.getUri('payload-passkeys-test')
    return async () => {
      await replSet.stop()
    }
  }

  if (adapter === 'sqlite' && !process.env.DATABASE_URL) {
    const dir = path.resolve('test/.tmp')
    mkdirSync(dir, { recursive: true })
    const file = path.join(dir, `int-${process.pid}.db`)
    process.env.DATABASE_URL = `file:${file}`
    return async () => {
      rmSync(file, { force: true })
    }
  }

  if (adapter === 'postgres' && !process.env.DATABASE_URL) {
    process.env.DATABASE_URL = 'postgres://postgres:postgres@127.0.0.1:5432/payload_passkeys'
  }
  return async () => {}
}
