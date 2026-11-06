import type { CollectionConfig } from 'payload'

import type { ResolvedOptions } from '../server/options.js'

const never = () => false

export const challengesCollection = (options: ResolvedOptions): CollectionConfig => ({
  slug: options.slugs.challenges,
  access: { create: never, delete: never, read: never, update: never },
  admin: { hidden: true },
  fields: [
    { name: 'challenge', type: 'text', required: true, unique: true },
    {
      name: 'type',
      type: 'select',
      index: true,
      options: ['registration', 'authentication'],
      required: true,
    },
    { name: 'collection', type: 'text', required: true },
    // Stored as text, not a relationship: the owner may be in any configured collection.
    { name: 'userId', type: 'text', index: true },
    { name: 'userHandle', type: 'text' },
    { name: 'browserKeyHash', type: 'text', index: true, required: true },
    { name: 'expiresAt', type: 'date', index: true, required: true },
  ],
  graphQL: false,
  lockDocuments: false,
  timestamps: true,
})
