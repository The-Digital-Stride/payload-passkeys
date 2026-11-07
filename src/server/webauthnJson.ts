import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server'

const B64URL = /^[A-Za-z0-9_-]+$/
/** Credential IDs are at most 1023 bytes (WebAuthn L3), 1364 base64url characters. */
const MAX_ID = 1364
const MAX_FIELD = 32 * 1024

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v)
const b64 = (v: unknown, max = MAX_FIELD): v is string =>
  typeof v === 'string' && v.length <= max && B64URL.test(v)

/** The challenge a client signed, read from clientDataJSON, or null. Verified again by the library. */
export const challengeFromClientData = (clientDataJSON: unknown): null | string => {
  if (!b64(clientDataJSON)) return null
  try {
    const parsed: unknown = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'))
    const challenge = isObj(parsed) ? parsed.challenge : undefined
    return typeof challenge === 'string' && /^[A-Za-z0-9_-]{43}$/.test(challenge) ? challenge : null
  } catch {
    return null
  }
}

const base = (
  value: unknown,
): null | { attachment?: string; ext: Obj; id: string; response: Obj } => {
  if (!isObj(value) || value.type !== 'public-key') return null
  if (!b64(value.id, MAX_ID) || value.rawId !== value.id || !isObj(value.response)) return null
  const ext = value.clientExtensionResults === undefined ? {} : value.clientExtensionResults
  if (!isObj(ext)) return null
  const attachment = value.authenticatorAttachment
  if (attachment !== undefined && attachment !== 'platform' && attachment !== 'cross-platform')
    return null
  return {
    attachment: attachment as string | undefined,
    ext,
    id: value.id,
    response: value.response,
  }
}

export const parseRegistrationResponse = (value: unknown): null | RegistrationResponseJSON => {
  const parsed = base(value)
  if (!parsed) return null
  const { attestationObject, clientDataJSON, transports } = parsed.response
  if (!b64(attestationObject) || !b64(clientDataJSON)) return null
  if (
    transports !== undefined &&
    !(
      Array.isArray(transports) &&
      transports.length <= 10 &&
      transports.every((t) => typeof t === 'string' && t.length <= 32)
    )
  ) {
    return null
  }
  return {
    authenticatorAttachment:
      parsed.attachment as RegistrationResponseJSON['authenticatorAttachment'],
    clientExtensionResults: parsed.ext as RegistrationResponseJSON['clientExtensionResults'],
    id: parsed.id,
    rawId: parsed.id,
    response: {
      attestationObject,
      clientDataJSON,
      ...(transports
        ? { transports: transports as RegistrationResponseJSON['response']['transports'] }
        : {}),
    },
    type: 'public-key',
  }
}

export const parseAuthenticationResponse = (value: unknown): AuthenticationResponseJSON | null => {
  const parsed = base(value)
  if (!parsed) return null
  const { authenticatorData, clientDataJSON, signature, userHandle } = parsed.response
  if (!b64(authenticatorData) || !b64(clientDataJSON) || !b64(signature)) return null
  if (userHandle !== undefined && !b64(userHandle, 128)) return null
  return {
    authenticatorAttachment:
      parsed.attachment as AuthenticationResponseJSON['authenticatorAttachment'],
    clientExtensionResults: parsed.ext as AuthenticationResponseJSON['clientExtensionResults'],
    id: parsed.id,
    rawId: parsed.id,
    response: {
      authenticatorData,
      clientDataJSON,
      signature,
      ...(userHandle ? { userHandle } : {}),
    },
    type: 'public-key',
  }
}
