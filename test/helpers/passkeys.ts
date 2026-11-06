import type { Payload } from 'payload'

import { randomBytes } from 'crypto'

/** Inserts a passkey row directly (no ceremony), for access and schema tests. */
export const insertPasskey = async (
  payload: Payload,
  {
    collection,
    userId,
    ...data
  }: { collection: string; userId: number | string } & Record<string, unknown>,
) => {
  const polymorphic = Array.isArray(
    (
      payload.collections.passkeys!.config.fields.find((f) => 'name' in f && f.name === 'user') as {
        relationTo: unknown
      }
    ).relationTo,
  )
  return (await payload.create({
    collection: 'passkeys',
    data: {
      backedUp: true,
      authCollection: collection,
      counter: 0,
      credentialId: randomBytes(16).toString('base64url'),
      deviceType: 'multiDevice',
      name: 'Test passkey',
      publicKey: randomBytes(77).toString('base64url'),
      rpID: 'localhost',
      transports: ['internal'],
      user: polymorphic ? { relationTo: collection, value: userId } : userId,
      userHandle: randomBytes(64).toString('base64url'),
      ...data,
    },
    overrideAccess: true,
  } as never)) as { credentialId: string; id: number | string }
}
