import type { Payload } from 'payload'

import { randomUUID } from 'crypto'

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
