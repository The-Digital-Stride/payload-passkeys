import type { CollectionAfterDeleteHook, CollectionConfig, Field } from 'payload'

import type { ResolvedOptions } from '../server/options.js'

import { ownPasskeysWhere } from './passkeys.js'
import { USER_HANDLE_FIELD } from '../shared/constants.js'

const never = () => false

/** The WebAuthn user.id: 64 random bytes, base64url. Not unique (Mongo sparse indexes collide on null). */
export const userHandleField: Field = {
  name: USER_HANDLE_FIELD,
  type: 'text',
  access: { create: never, read: never, update: never },
  admin: { disabled: true, hidden: true },
}

const removePasskeysOfDeletedUser =
  (options: ResolvedOptions, collectionSlug: string): CollectionAfterDeleteHook =>
  async ({ id, req }) => {
    try {
      await req.payload.db.deleteMany({
        collection: options.slugs.passkeys,
        req,
        where: ownPasskeysWhere(options, collectionSlug, id),
      })
      await req.payload.db.deleteMany({
        collection: options.slugs.challenges,
        req,
        where: {
          and: [{ collection: { equals: collectionSlug } }, { userId: { equals: String(id) } }],
        },
      })
    } catch (error) {
      req.payload.logger.error({
        err: error,
        msg: 'passkeys: failed to remove the passkeys of a deleted user',
      })
    }
  }

export const withPasskeyFields = (
  collection: CollectionConfig,
  options: ResolvedOptions,
  extraFields: Field[] = [],
): CollectionConfig => ({
  ...collection,
  fields: [...collection.fields, userHandleField, ...extraFields],
  hooks: {
    ...collection.hooks,
    afterDelete: [
      ...(collection.hooks?.afterDelete ?? []),
      removePasskeysOfDeletedUser(options, collection.slug),
    ],
  },
})
