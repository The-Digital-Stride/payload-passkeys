import type { CollectionConfig } from 'payload'

import type { ResolvedOptions } from '../server/options.js'

const never = () => false

/**
 * Consuming a challenge is a unique insert here. A unique-constraint error means the challenge was
 * already used. Atomic on every adapter, unlike find-then-delete on Drizzle (review M3).
 */
export const challengeUsesCollection = (options: ResolvedOptions): CollectionConfig => ({
  slug: options.slugs.challengeUses,
  access: { create: never, delete: never, read: never, update: never },
  admin: { hidden: true },
  fields: [
    { name: 'challenge', type: 'text', required: true, unique: true },
    { name: 'expiresAt', type: 'date', index: true, required: true },
  ],
  graphQL: false,
  lockDocuments: false,
  timestamps: true,
})
