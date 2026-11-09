import type { CollectionBeforeDeleteHook, CollectionConfig, Field } from 'payload'

import type { Reauthentication } from '../types.js'
import type { ResolvedOptions } from '../server/options.js'

import { logEvent } from '../server/logging.js'
import {
  dropRevokedSessions,
  hideRevokedSessions,
  refuseRevokedRefresh,
} from '../server/sessions.js'
import { ownPasskeysWhere } from './passkeys.js'
import { MANAGER_FIELD, PACKAGE_NAME, USER_HANDLE_FIELD } from '../shared/constants.js'

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
 *
 * The opposite can happen: Payload checks the document lock after beforeDelete, and the lock check
 * isn't exported. On an adapter without transactions (SQLite by default, standalone MongoDB) a
 * delete refused for a lock still loses the passkeys. That fails safe (the password still works),
 * and the log line below records it.
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
        and: [{ authCollection: { equals: collectionSlug } }, { userId: { equals: String(id) } }],
      },
    })
    logEvent(req, options, 'passkeys.removed', {
      collection: collectionSlug,
      reason: 'user_deleted',
      userId: id,
    })
  }

/**
 * The Passkeys section. The RSC wrapper renders it on the signed-in user's own document only
 * (Verified facts Q2); a `ui` field stores nothing, so adding or removing it changes no schema.
 */
export const managerField = (
  collectionSlug: string,
  reauthentication: Reauthentication = 'password',
): Field => ({
  name: MANAGER_FIELD,
  type: 'ui',
  admin: {
    components: {
      Field: {
        // Only sent when it isn't the default; the component assumes 'password'.
        clientProps:
          reauthentication === 'password'
            ? { collectionSlug }
            : { collectionSlug, reauthentication },
        path: `${PACKAGE_NAME}/rsc#PasskeysManagerField`,
      },
    },
    disableListColumn: true,
  },
})

export const withPasskeyFields = (
  collection: CollectionConfig,
  options: ResolvedOptions,
): CollectionConfig => ({
  ...collection,
  fields: [
    ...collection.fields,
    userHandleField,
    ...(options.enabled ? [managerField(collection.slug, options.reauthentication)] : []),
  ],
  hooks: {
    ...collection.hooks,
    // Always, even when disabled: the reset command revokes sessions too.
    afterOperation: [...(collection.hooks?.afterOperation ?? []), hideRevokedSessions(options)],
    afterRefresh: [...(collection.hooks?.afterRefresh ?? []), refuseRevokedRefresh(options)],
    beforeChange: [...(collection.hooks?.beforeChange ?? []), dropRevokedSessions(options)],
    beforeDelete: [
      ...(collection.hooks?.beforeDelete ?? []),
      removePasskeysOfUser(options, collection.slug),
    ],
  },
})
