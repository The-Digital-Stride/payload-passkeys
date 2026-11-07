import type { Payload } from 'payload'

import { randomUUID } from 'crypto'
import { vi } from 'vitest'

export const PASSWORD = 'correct horse battery staple'

export type TestUser = { collection: string; email: string; id: number | string }

export const createUser = async (
  payload: Payload,
  collection: 'customers' | 'users',
  data: Record<string, unknown> = {},
): Promise<TestUser> => {
  const email = `${collection}-${randomUUID()}@example.test`
  const doc = (await payload.create({
    collection,
    data: {
      email,
      password: PASSWORD,
      ...(collection === 'users' ? { name: 'Test User' } : {}),
      ...data,
    },
    disableVerificationEmail: true,
  } as never)) as { id: number | string }
  if (collection === 'customers') {
    await payload.db.updateOne({
      collection,
      data: { _verified: true },
      id: doc.id,
      returning: false,
    })
  }
  return { collection, email, id: doc.id }
}

export const rawUser = async (payload: Payload, collection: string, id: number | string) =>
  (await payload.db.findOne({ collection, where: { id: { equals: id } } })) as Record<
    string,
    unknown
  > & {
    loginAttempts?: number
    lockUntil?: null | string
    sessions?: { createdAt?: string; expiresAt: string; id: string }[]
  }

type StoredSession = { createdAt?: string; expiresAt: string; id: string }

type SessionWrite = {
  /** The real session write. */
  write: () => Promise<unknown>
  /** Stores `sessions` as the user's sessions, past the interception, in the same transaction. */
  writeSessions: (sessions: StoredSession[]) => Promise<unknown>
}

type MongoModel = {
  findOneAndUpdate: (
    filter: Record<string, unknown>,
    update: Record<string, unknown>,
    options: Record<string, unknown>,
  ) => PromiseLike<unknown>
}

/**
 * Intercepts revokeSessions' session write to `collection`: on Postgres and SQLite the
 * payload.db.updateOne whose data carries a `sessions` array; on MongoDB, which removes sessions
 * with one atomic update through the adapter's Mongoose model, that model's findOneAndUpdate with
 * a `$pull` of, or a `$set` of only, `sessions`. Other writes pass through. Returns the spy.
 */
export const interceptSessionWrites = (
  payload: Payload,
  collection: string,
  handle: (write: SessionWrite) => Promise<unknown>,
) => {
  if (payload.db.name === 'mongoose') {
    const model = (payload.db as unknown as { collections: Record<string, MongoModel> })
      .collections[collection]!
    const original = model.findOneAndUpdate.bind(model)
    const isSessionWrite = (update: Record<string, unknown>) => {
      const pull = update.$pull as Record<string, unknown> | undefined
      const set = update.$set as Record<string, unknown> | undefined
      if (pull && 'sessions' in pull) return true
      return Object.keys(update).join() === '$set' && Object.keys(set ?? {}).join() === 'sessions'
    }
    return vi.spyOn(model, 'findOneAndUpdate').mockImplementation((filter, update, options) =>
      isSessionWrite(update)
        ? handle({
            write: async () => original(filter, update, options),
            writeSessions: async (sessions) =>
              original(filter, { $set: { sessions } }, { ...options, lean: true }),
          })
        : original(filter, update, options),
    )
  }
  const updateOne = payload.db.updateOne.bind(payload.db)
  return vi.spyOn(payload.db, 'updateOne').mockImplementation(async (args) =>
    args.collection === collection && Array.isArray((args.data as { sessions?: unknown }).sessions)
      ? (handle({
          write: () => updateOne(args),
          writeSessions: (sessions) => updateOne({ ...args, data: { sessions } }),
        }) as ReturnType<typeof updateOne>)
      : updateOne(args),
  )
}
