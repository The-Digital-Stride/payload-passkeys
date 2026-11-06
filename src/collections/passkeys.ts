import type { Access, CollectionConfig, Field, Where } from 'payload'

import type { ResolvedOptions } from '../server/options.js'

import { MAX_PASSKEY_NAME } from '../shared/constants.js'

const never = () => false

/** Own passkeys only, matching collection and ID together: IDs collide across SQL tables (H3). */
export const ownPasskeysWhere = (
  options: ResolvedOptions,
  collection: string,
  id: number | string,
): Where => ({
  and: [
    { collection: { equals: collection } },
    options.collections.length === 1
      ? { user: { equals: id } }
      : { and: [{ 'user.relationTo': { equals: collection } }, { 'user.value': { equals: id } }] },
  ],
})

const readOwn =
  (options: ResolvedOptions): Access =>
  ({ req: { user } }) => {
    if (!user || !options.collections.includes(user.collection)) return false
    return ownPasskeysWhere(options, user.collection, user.id)
  }

/** One collection: a plain relationship. Several: polymorphic, so IDs can't collide (H3). */
const ownerField = (options: ResolvedOptions): Field => {
  const base = { name: 'user', index: true, maxDepth: 0, required: true } as const
  const [only] = options.collections
  return options.collections.length === 1 && only
    ? { ...base, type: 'relationship', relationTo: only }
    : { ...base, type: 'relationship', relationTo: options.collections }
}

export const passkeysCollection = (options: ResolvedOptions): CollectionConfig => ({
  slug: options.slugs.passkeys,
  access: { create: never, delete: never, read: readOwn(options), update: never },
  admin: { hidden: true, useAsTitle: 'name' },
  fields: [
    ownerField(options),
    // The owner's collection slug, checked before anything else (H3).
    { name: 'collection', type: 'text', index: true, required: true },
    { name: 'credentialId', type: 'text', required: true, unique: true },
    // The WebAuthn user.id this passkey was made with (L4). Compared with each assertion.
    { name: 'userHandle', type: 'text', access: { read: never }, required: true },
    { name: 'publicKey', type: 'text', access: { read: never }, required: true },
    { name: 'counter', type: 'number', access: { read: never }, defaultValue: 0, required: true },
    { name: 'transports', type: 'json' },
    {
      name: 'deviceType',
      type: 'select',
      options: ['singleDevice', 'multiDevice'],
      required: true,
    },
    { name: 'backedUp', type: 'checkbox', defaultValue: false },
    { name: 'aaguid', type: 'text' },
    { name: 'rpID', type: 'text', required: true },
    { name: 'name', type: 'text', maxLength: MAX_PASSKEY_NAME, required: true },
    { name: 'lastUsedAt', type: 'date' },
  ],
  graphQL: false,
  lockDocuments: false,
  timestamps: true,
})
