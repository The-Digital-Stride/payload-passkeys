import { describe, expect, it, vi } from 'vitest'

import type { Api, Browser } from '../../src/components/shared/flows.js'

import {
  registerFlow,
  signInFlow,
  syncAcceptedCredentials,
} from '../../src/components/shared/flows.js'

const reply = (status: number, data: Record<string, unknown> = {}) => ({
  data,
  ok: status < 400,
  status,
})
const browser = (overrides: Partial<Browser> = {}): Browser => ({
  sendSignal: vi.fn(async () => undefined),
  startAuthentication: vi.fn(async () => ({ id: 'cred' }) as never),
  startRegistration: vi.fn(async () => ({ id: 'cred' }) as never),
  ...overrides,
})
const cancelled = Object.assign(new Error('The operation either timed out or was not allowed.'), {
  name: 'NotAllowedError',
})

describe('signInFlow', () => {
  it('returns the session body on success', async () => {
    const api: Api = vi.fn(async (path) =>
      path.endsWith('/options')
        ? reply(200, { options: { challenge: 'c', rpId: 'localhost' } })
        : reply(200, { exp: 1, user: { id: 1 } }),
    )
    expect(await signInFlow({ api, browser: browser() })).toEqual({
      body: { exp: 1, user: { id: 1 } },
      ok: true,
    })
  })

  it('says cancelled when the person dismisses the prompt', async () => {
    const api: Api = vi.fn(async () => reply(200, { options: { rpId: 'localhost' } }))
    expect(
      await signInFlow({
        api,
        browser: browser({ startAuthentication: vi.fn(async () => Promise.reject(cancelled)) }),
      }),
    ).toEqual({ message: 'signInCancelled', ok: false })
  })

  it('signals an unknown credential and shows the generic failure', async () => {
    const b = browser()
    const api: Api = vi.fn(async (path) =>
      path.endsWith('/options')
        ? reply(200, { options: { rpId: 'localhost' } })
        : reply(400, { error: 'sign_in_failed', unknownCredential: true }),
    )
    expect(await signInFlow({ api, browser: b })).toEqual({ message: 'signInFailed', ok: false })
    expect(b.sendSignal).toHaveBeenCalledWith({
      credentialID: 'cred',
      rpID: 'localhost',
      signalName: 'unknownCredential',
    })
  })

  it('maps busy and rate limits', async () => {
    expect(
      await signInFlow({
        api: vi.fn(async () => reply(429, { error: 'busy' })),
        browser: browser(),
      }),
    ).toEqual({ message: 'busy', ok: false })
    expect(
      await signInFlow({
        api: vi.fn(async () => reply(429, { error: 'rate_limited' })),
        browser: browser(),
      }),
    ).toEqual({ message: 'rateLimited', ok: false })
  })

  it('shows the generic failure while passkeys are off (503 unavailable)', async () => {
    const off = browser()
    expect(
      await signInFlow({
        api: vi.fn(async () => reply(503, { error: 'unavailable' })),
        browser: off,
      }),
    ).toEqual({ message: 'signInFailed', ok: false })
    expect(off.startAuthentication).not.toHaveBeenCalled()
    expect(
      await registerFlow({
        api: vi.fn(async () => reply(503, { error: 'unavailable' })),
        askPassword: vi.fn(async () => null),
        browser: off,
        onReauthenticated: vi.fn(),
      }),
    ).toEqual({ message: 'addFailed', ok: false })
    expect(off.startRegistration).not.toHaveBeenCalled()
  })
})

describe('registerFlow', () => {
  it('asks for the password when the session is stale, then registers', async () => {
    const calls: string[] = []
    let fresh = false
    const api: Api = vi.fn(async (path, body) => {
      calls.push(path)
      if (path.endsWith('/register/options'))
        return fresh ? reply(200, { options: {} }) : reply(403, { error: 'reauth_required' })
      if (path.endsWith('/reauth'))
        return (body as { password: string }).password === 'right'
          ? ((fresh = true), reply(200, { exp: 2, user: { id: 1 } }))
          : reply(401, { error: 'reauth_failed' })
      return reply(200, { passkey: { id: 9 } })
    })
    const askPassword = vi.fn().mockResolvedValueOnce('wrong').mockResolvedValueOnce('right')
    const onReauthenticated = vi.fn()
    const result = await registerFlow({ api, askPassword, browser: browser(), onReauthenticated })
    expect(result).toEqual({ ok: true, passkey: { id: 9 } })
    expect(askPassword.mock.calls).toEqual([[undefined], ['wrongPassword']])
    expect(onReauthenticated).toHaveBeenCalledWith({ exp: 2, user: { id: 1 } })
    expect(calls.map((c) => c.split('/passkeys/')[1])).toEqual([
      'register/options',
      'reauth',
      'reauth',
      'register/options',
      'register/verify',
    ])
  })

  it('stops quietly when the password prompt is dismissed', async () => {
    const api: Api = vi.fn(async () => reply(403, { error: 'reauth_required' }))
    expect(
      await registerFlow({
        api,
        askPassword: async () => null,
        browser: browser(),
        onReauthenticated: vi.fn(),
      }),
    ).toEqual({ message: 'addCancelled', ok: false })
  })

  it.each([
    [reply(409, { error: 'too_many_passkeys' }), undefined, 'tooMany'],
    [
      reply(200, { options: {} }),
      Object.assign(new Error('x'), {
        code: 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED',
        name: 'InvalidStateError',
      }),
      'alreadyOnDevice',
    ],
    [reply(200, { options: {} }), cancelled, 'addCancelled'],
    [reply(200, { options: {} }), new Error('boom'), 'addFailed'],
  ])('maps failures (%#)', async (optionsReply, browserError, message) => {
    const api: Api = vi.fn(async () => optionsReply)
    const b = browser(
      browserError ? { startRegistration: vi.fn(async () => Promise.reject(browserError)) } : {},
    )
    expect(
      await registerFlow({
        api,
        askPassword: async () => null,
        browser: b,
        onReauthenticated: vi.fn(),
      }),
    ).toEqual({ message, ok: false })
  })
})

describe('syncAcceptedCredentials', () => {
  it('sends the signal and never throws', async () => {
    const b = browser({ sendSignal: vi.fn(async () => Promise.reject(new Error('unsupported'))) })
    await expect(
      syncAcceptedCredentials(b, { credentialIds: ['a'], rpID: 'localhost', userId: 'h' }),
    ).resolves.toBeUndefined()
    expect(b.sendSignal).toHaveBeenCalledWith({
      allAcceptedCredentialIDs: ['a'],
      rpID: 'localhost',
      signalName: 'allAcceptedCredentials',
      userID: 'h',
    })
  })
})
