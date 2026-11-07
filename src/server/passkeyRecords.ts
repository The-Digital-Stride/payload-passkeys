import type { PayloadRequest } from 'payload'

import type { DeviceType, PublicPasskey } from '../types.js'
import type { ResolvedOptions } from './options.js'

import { ownPasskeysWhere } from '../collections/passkeys.js'

type Ref = number | string | { id: number | string }

export type PasskeyRow = {
  aaguid?: null | string
  backedUp: boolean
  authCollection: string
  counter: number
  createdAt: string
  credentialId: string
  deviceType: DeviceType
  id: number | string
  lastUsedAt?: null | string
  name: string
  publicKey: string
  rpID: string
  transports?: null | string[]
  user: { relationTo: string; value: Ref } | Ref
  userHandle: string
}

const idOf = (ref: Ref | null | undefined): null | number | string =>
  ref === null || ref === undefined ? null : typeof ref === 'object' ? ref.id : ref

/** The row's owner. Null when the relationship and the collection column disagree (H3). */
export const ownerOf = (row: PasskeyRow): null | { collection: string; id: number | string } => {
  const { user } = row
  if (user && typeof user === 'object' && 'relationTo' in user) {
    if (user.relationTo !== row.authCollection) return null
    const id = idOf(user.value)
    return id === null ? null : { collection: row.authCollection, id }
  }
  const id = idOf(user as Ref)
  return id === null ? null : { collection: row.authCollection, id }
}

export const toPublicPasskey = (row: PasskeyRow): PublicPasskey => ({
  aaguid: row.aaguid ?? null,
  backedUp: Boolean(row.backedUp),
  createdAt: row.createdAt,
  credentialId: row.credentialId,
  deviceType: row.deviceType,
  id: row.id,
  lastUsedAt: row.lastUsedAt ?? null,
  name: row.name,
  rpID: row.rpID,
  transports: Array.isArray(row.transports) ? row.transports : [],
})

/** Every field, including key material. Server use only. */
export const findPasskeyByCredentialId = async (
  req: PayloadRequest,
  options: ResolvedOptions,
  credentialId: string,
): Promise<null | PasskeyRow> => {
  const { docs } = await req.payload.find({
    collection: options.slugs.passkeys as never,
    depth: 0,
    limit: 1,
    overrideAccess: true,
    pagination: false,
    req,
    where: { credentialId: { equals: credentialId } },
  })
  return (docs[0] as PasskeyRow | undefined) ?? null
}

export const listPasskeysOfUser = async (
  req: PayloadRequest,
  options: ResolvedOptions,
  collection: string,
  userId: number | string,
): Promise<PasskeyRow[]> => {
  const { docs } = await req.payload.find({
    collection: options.slugs.passkeys as never,
    depth: 0,
    limit: 0,
    overrideAccess: true,
    pagination: false,
    req,
    sort: '-createdAt',
    where: ownPasskeysWhere(options, collection, userId),
  })
  return docs as PasskeyRow[]
}

/** One of this user's passkeys by row ID, or null. Collection and ID are both matched (H3). */
export const findOwnPasskey = async (
  req: PayloadRequest,
  options: ResolvedOptions,
  collection: string,
  userId: number | string,
  id: unknown,
): Promise<null | PasskeyRow> => {
  if ((typeof id !== 'string' && typeof id !== 'number') || String(id).length > 64) return null
  const { docs } = await req.payload.find({
    collection: options.slugs.passkeys as never,
    depth: 0,
    limit: 1,
    overrideAccess: true,
    pagination: false,
    req,
    where: { and: [{ id: { equals: id } }, ownPasskeysWhere(options, collection, userId)] },
  })
  return (docs[0] as PasskeyRow | undefined) ?? null
}
