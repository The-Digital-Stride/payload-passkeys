import type { ResolvedOptions } from '../options.js'
import type { PasskeyRow } from '../passkeyRecords.js'

import { ENDPOINTS } from '../../shared/constants.js'
import { EndpointError, json, passkeyEndpoint } from '../http.js'
import { logEvent } from '../logging.js'
import { findOwnPasskey, toPublicPasskey } from '../passkeyRecords.js'
import { cleanPasskeyName } from './registerVerify.js'

export const renameEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'rename',
    auth: 'signed-in',
    collectionSlug,
    handler: async ({ body, req, user }) => {
      const name = cleanPasskeyName(body.name)
      if (!name) throw new EndpointError(400, 'bad_request')
      const row = await findOwnPasskey(req, options, collectionSlug, user.id, body.id)
      if (!row) throw new EndpointError(404, 'not_found')
      const updated = (await req.payload.update({
        collection: options.slugs.passkeys as never,
        data: { name } as never,
        depth: 0,
        id: row.id,
        overrideAccess: true,
        req,
      })) as unknown as PasskeyRow
      logEvent(req, options, 'passkeys.renamed', {
        collection: collectionSlug,
        credentialId: row.credentialId,
        userId: user.id,
      })
      return json(req, 200, { passkey: toPublicPasskey(updated) })
    },
    options,
    path: ENDPOINTS.rename,
  })
