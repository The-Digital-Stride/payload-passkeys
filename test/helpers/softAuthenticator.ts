import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server'

import { isoBase64URL, isoCBOR } from '@simplewebauthn/server/helpers'

const FLAG_UP = 0x01
const FLAG_UV = 0x04
const FLAG_BE = 0x08
const FLAG_BS = 0x10
const FLAG_AT = 0x40

export type CeremonyOverrides = {
  /** Sign with a different key than the stored one (bad signature). */
  badSignature?: boolean
  backupEligible?: boolean
  backupState?: boolean
  /** Replace the challenge in clientDataJSON. */
  challenge?: string
  /** Set the counter explicitly for this ceremony instead of incrementing. */
  counter?: number
  /** credProps.rk reported to the server (registration only). null omits credProps. */
  credPropsRk?: boolean | null
  origin?: string
  rpID?: string
  type?: string
  userHandle?: null | string
  userPresent?: boolean
  userVerified?: boolean
}

type StoredCredential = {
  backupEligible: boolean
  backupState: boolean
  counter: number
  id: Uint8Array
  privateKey: CryptoKey
  publicKey: CryptoKey
  rpID: string
  userHandle: string
}

export type SoftAuthenticatorOptions = {
  aaguid?: string
  backupEligible?: boolean
  backupState?: boolean
  /** Counters stay 0 (like a synced passkey) unless this is set. */
  incrementCounter?: boolean
  origin: string
}

const enc = new TextEncoder()

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

const u32 = (n: number): Uint8Array => {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, false)
  return b
}

const u16 = (n: number): Uint8Array => {
  const b = new Uint8Array(2)
  new DataView(b.buffer).setUint16(0, n, false)
  return b
}

const sha256 = async (data: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', data))

const aaguidBytes = (aaguid: string): Uint8Array => {
  const hex = aaguid.replace(/-/g, '')
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new Error(`Bad AAGUID ${aaguid}`)
  return Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)))
}

/** DER-encode a raw (r || s) P-256 signature, which is what WebAuthn ES256 requires. */
const rawToDer = (raw: Uint8Array): Uint8Array => {
  const int = (bytes: Uint8Array): Uint8Array => {
    let i = 0
    while (i < bytes.length - 1 && bytes[i] === 0) i++
    let v = bytes.slice(i)
    if (v[0]! & 0x80) v = concat(new Uint8Array([0]), v)
    return concat(new Uint8Array([0x02, v.length]), v)
  }
  const body = concat(int(raw.slice(0, 32)), int(raw.slice(32)))
  return concat(new Uint8Array([0x30, body.length]), body)
}

const coseES256 = async (publicKey: CryptoKey): Promise<Uint8Array> => {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey)) // 0x04 || x || y
  return isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, raw.slice(1, 33)], // x
      [-3, raw.slice(33, 65)], // y
    ]),
  )
}

const flagsByte = (o: {
  at?: boolean
  be: boolean
  bs: boolean
  up: boolean
  uv: boolean
}): number =>
  (o.up ? FLAG_UP : 0) |
  (o.uv ? FLAG_UV : 0) |
  (o.be ? FLAG_BE : 0) |
  (o.bs ? FLAG_BS : 0) |
  (o.at ? FLAG_AT : 0)

const clientData = (type: string, challenge: string, origin: string): Uint8Array =>
  enc.encode(JSON.stringify({ type, challenge, origin, crossOrigin: false }))

/**
 * A software WebAuthn authenticator for integration tests: ES256 keys from WebCrypto,
 * attestation "none", and full control over every flag the server must check.
 */
export const createSoftAuthenticator = (options: SoftAuthenticatorOptions) => {
  const aaguid = options.aaguid ?? '00000000-0000-0000-0000-000000000000'
  const credentials = new Map<string, StoredCredential>()

  const register = async (
    optionsJSON: PublicKeyCredentialCreationOptionsJSON,
    o: CeremonyOverrides = {},
  ): Promise<RegistrationResponseJSON> => {
    const keyPair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const id = crypto.getRandomValues(new Uint8Array(32))
    const rpID = o.rpID ?? optionsJSON.rp.id ?? new URL(options.origin).hostname
    const be = o.backupEligible ?? options.backupEligible ?? true
    const bs = o.backupState ?? options.backupState ?? be
    const counter = o.counter ?? 0

    const authData = concat(
      await sha256(enc.encode(rpID)),
      new Uint8Array([
        flagsByte({ at: true, be, bs, up: o.userPresent ?? true, uv: o.userVerified ?? true }),
      ]),
      u32(counter),
      aaguidBytes(aaguid),
      u16(id.length),
      id,
      await coseES256(keyPair.publicKey),
    )
    const attestationObject = isoCBOR.encode(
      new Map<string, Map<string, never> | number | string | Uint8Array>([
        ['fmt', 'none'],
        ['attStmt', new Map<string, never>()],
        ['authData', authData],
      ]),
    )
    const cdj = clientData(
      o.type ?? 'webauthn.create',
      o.challenge ?? optionsJSON.challenge,
      o.origin ?? options.origin,
    )
    const credentialId = isoBase64URL.fromBuffer(id)
    credentials.set(credentialId, {
      backupEligible: be,
      backupState: bs,
      counter,
      id,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      rpID,
      userHandle: optionsJSON.user.id,
    })

    const rk = o.credPropsRk === undefined ? true : o.credPropsRk
    return {
      authenticatorAttachment: 'platform',
      clientExtensionResults: rk === null ? {} : { credProps: { rk } },
      id: credentialId,
      rawId: credentialId,
      response: {
        attestationObject: isoBase64URL.fromBuffer(attestationObject),
        authenticatorData: isoBase64URL.fromBuffer(authData),
        clientDataJSON: isoBase64URL.fromBuffer(cdj),
        publicKeyAlgorithm: -7,
        transports: ['internal', 'hybrid'],
      },
      type: 'public-key',
    }
  }

  const authenticate = async (
    optionsJSON: PublicKeyCredentialRequestOptionsJSON,
    o: CeremonyOverrides & { credentialId?: string } = {},
  ): Promise<AuthenticationResponseJSON> => {
    const credentialId = o.credentialId ?? [...credentials.keys()].at(-1)
    const cred = credentialId ? credentials.get(credentialId) : undefined
    if (!credentialId || !cred) throw new Error('Soft authenticator has no such credential')

    if (o.counter !== undefined) cred.counter = o.counter
    else if (options.incrementCounter) cred.counter += 1

    const rpID = o.rpID ?? optionsJSON.rpId ?? cred.rpID
    const be = o.backupEligible ?? cred.backupEligible
    const bs = o.backupState ?? cred.backupState
    const authData = concat(
      await sha256(enc.encode(rpID)),
      new Uint8Array([
        flagsByte({ be, bs, up: o.userPresent ?? true, uv: o.userVerified ?? true }),
      ]),
      u32(cred.counter),
    )
    const cdj = clientData(
      o.type ?? 'webauthn.get',
      o.challenge ?? optionsJSON.challenge,
      o.origin ?? options.origin,
    )
    const signingKey = o.badSignature
      ? (
          (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
            'sign',
          ])) as CryptoKeyPair
        ).privateKey
      : cred.privateKey
    const signed = concat(authData, await sha256(cdj))
    const raw = new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKey, signed),
    )
    const userHandle = o.userHandle === undefined ? cred.userHandle : o.userHandle

    return {
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      id: credentialId,
      rawId: credentialId,
      response: {
        authenticatorData: isoBase64URL.fromBuffer(authData),
        clientDataJSON: isoBase64URL.fromBuffer(cdj),
        signature: isoBase64URL.fromBuffer(rawToDer(raw)),
        ...(userHandle === null ? {} : { userHandle }),
      },
      type: 'public-key',
    }
  }

  return {
    authenticate,
    credentialIds: () => [...credentials.keys()],
    forget: (credentialId: string) => credentials.delete(credentialId),
    register,
  }
}

export type SoftAuthenticator = ReturnType<typeof createSoftAuthenticator>
