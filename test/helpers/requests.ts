import type { PayloadRequest, SanitizedConfig } from 'payload'

import { createPayloadRequest } from 'payload'

import type { TestClient } from './api.js'

import { SERVER_URL } from './api.js'

/** A PayloadRequest authenticated by the client's cookies, as an endpoint would see it. */
export const requestFor = async (
  config: Promise<SanitizedConfig>,
  path: string,
  client?: TestClient,
): Promise<PayloadRequest> => {
  const headers = new Headers({ 'Content-Type': 'application/json', Origin: SERVER_URL })
  if (client?.cookies.size) {
    headers.set('Cookie', [...client.cookies].map(([n, v]) => `${n}=${v}`).join('; '))
  }
  return createPayloadRequest({
    config,
    request: new Request(`${SERVER_URL}${path}`, { headers, method: 'POST' }),
  })
}

export const missingUserId = (): number | string =>
  (process.env.DATABASE_ADAPTER ?? 'mongo') === 'mongo' ? '000000000000000000000000' : 999_999_999
