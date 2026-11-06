import type { CollectionBeforeDeleteHook, CollectionConfig, Field } from 'payload'

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

/**
 * Runs in beforeDelete, inside the delete's transaction and after Payload's access check: on SQL
 * the user's row can't go first, because passkeys.user_id is NOT NULL (single collection) and the
 * polymorphic _rels rows cascade away before an afterDelete hook could find them. Errors propagate
 * so the user is never deleted with passkeys left behind.
 */
const removePasskeysOfUser =
  (options: ResolvedOptions, collectionSlug: string): CollectionBeforeDeleteHook =>
  async ({ id, req }) => {
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
    beforeDelete: [
      ...(collection.hooks?.beforeDelete ?? []),
      removePasskeysOfUser(options, collection.slug),
    ],
  },
})
