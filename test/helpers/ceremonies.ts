import type { Payload, SanitizedConfig } from 'payload'

import type { TestClient } from './api.js'
import type { CeremonyOverrides, SoftAuthenticator } from './softAuthenticator.js'

import { createClient } from './api.js'
import { PASSWORD, rawUser } from './users.js'

type Config = Promise<SanitizedConfig>

export const passwordClient = async (
  config: Config,
  collection: string,
  email: string,
): Promise<TestClient> => {
  const client = createClient(config)
  const res = await client.post(`/api/${collection}/login`, { email, password: PASSWORD })
  if (res.status !== 200) throw new Error(`login failed: ${res.status} ${JSON.stringify(res.json)}`)
  return client
}

/** Moves a user's newest session's createdAt into the past, to make it stale. */
export const ageNewestSession = async (
  payload: Payload,
  collection: string,
  userId: number | string,
  minutes: number,
) => {
  const { sessions = [] } = await rawUser(payload, collection, userId)
  const newest = sessions.at(-1)!
  newest.createdAt = new Date(Date.now() - minutes * 60_000).toISOString()
  await payload.db.updateOne({ collection, data: { sessions }, id: userId, returning: false })
}

export const registerPasskey = async (
  client: TestClient,
  authenticator: SoftAuthenticator,
  {
    collection = 'users',
    name,
    overrides,
  }: { collection?: string; name?: string; overrides?: CeremonyOverrides } = {},
) => {
  const options = await client.post(`/api/${collection}/passkeys/register/options`)
  if (options.status !== 200) return { options, verify: null }
  const response = await authenticator.register(options.json.options, overrides)
  const verify = await client.post(`/api/${collection}/passkeys/register/verify`, {
    name,
    response,
  })
  return { options, response, verify }
}

export const signInWithPasskey = async (
  client: TestClient,
  authenticator: SoftAuthenticator,
  {
    collection = 'users',
    overrides,
  }: { collection?: string; overrides?: CeremonyOverrides & { credentialId?: string } } = {},
) => {
  const options = await client.post(`/api/${collection}/passkeys/sign-in/options`)
  if (options.status !== 200) return { options, response: null, verify: null }
  const response = await authenticator.authenticate(options.json.options, overrides)
  const verify = await client.post(`/api/${collection}/passkeys/sign-in/verify`, { response })
  return { options, response, verify }
}
