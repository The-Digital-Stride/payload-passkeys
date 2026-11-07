import type { PayloadRequest } from 'payload'

import { describe, expect, it, vi } from 'vitest'

import type { ResolvedOptions } from '../../src/server/options.js'

import {
  hideRevokedSessions,
  isWriteConflict,
  MARKER_LOOKUP_CHUNK,
  revokedSessionMarker,
} from '../../src/server/sessions.js'

describe('isWriteConflict', () => {
  it('recognises lost writes on every adapter, through the cause chain', () => {
    const wrapped = (cause: unknown) => Object.assign(new Error('Failed query'), { cause })
    expect(isWriteConflict(wrapped({ code: '40P01', message: 'deadlock detected' }))).toBe(true)
    expect(isWriteConflict(wrapped({ code: '40001' }))).toBe(true)
    expect(isWriteConflict({ code: '23505' })).toBe(true)
    expect(isWriteConflict({ code: 'SQLITE_BUSY' })).toBe(true)
    expect(isWriteConflict({ code: 112, codeName: 'WriteConflict' })).toBe(true)
    expect(
      isWriteConflict({ hasErrorLabel: (label: string) => label === 'TransientTransactionError' }),
    ).toBe(true)
    expect(isWriteConflict({ data: { errors: [{ path: 'id' }] }, name: 'ValidationError' })).toBe(
      true,
    )
  })

  it('leaves other errors alone', () => {
    expect(isWriteConflict(new Error('connection refused'))).toBe(false)
    expect(
      isWriteConflict({ data: { errors: [{ path: 'email' }] }, name: 'ValidationError' }),
    ).toBe(false)
    expect(isWriteConflict(null)).toBe(false)
    expect(isWriteConflict('deadlock')).toBe(false)
  })
})

describe('revokedSessionMarker', () => {
  it('can never equal a base64url challenge', () => {
    expect(revokedSessionMarker('users', 'abc')).toBe('session:users:abc')
    expect(revokedSessionMarker('users', 'abc')).not.toMatch(/^[\w-]+$/)
  })
})

describe('hideRevokedSessions', () => {
  const options = { slugs: { challengeUses: 'passkey-challenge-uses' } } as ResolvedOptions
  const collection = { slug: 'users' } as never

  /** A req whose marker lookup answers from `marked`, or fails on the call numbered `failOn`. */
  const fakeReq = (marked: Set<string>, failOn?: number) => {
    const find = vi.fn(async ({ where }: { where: { challenge: { in: string[] } } }) => {
      if (find.mock.calls.length === failOn) throw new Error('too many SQL variables')
      return {
        docs: where.challenge.in.filter((c) => marked.has(c)).map((challenge) => ({ challenge })),
      }
    })
    const req = {
      payload: { db: { find }, logger: { warn: vi.fn() } },
    } as unknown as PayloadRequest
    return { find, req }
  }

  /** `users` user documents with `perUser` sessions each, ids `u<user>-s<session>`. */
  const findResult = (users: number, perUser: number) => ({
    docs: Array.from({ length: users }, (_, u) => ({
      id: u,
      sessions: Array.from({ length: perUser }, (_, s) => ({ id: `u${u}-s${s}` })),
    })),
  })

  const run = (req: PayloadRequest, result: unknown) =>
    hideRevokedSessions(options)({ collection, operation: 'find', req, result } as never)

  it('splits a large find into lookups of at most MARKER_LOOKUP_CHUNK ids, honouring every one', async () => {
    const result = findResult(5, 250) // 1250 sessions: three lookups
    const revoked = ['u0-s0', 'u2-s100', 'u4-s249']
    const { find, req } = fakeReq(new Set(revoked.map((sid) => revokedSessionMarker('users', sid))))

    await run(req, result)

    expect(find.mock.calls.length).toBeGreaterThan(1)
    expect(find).toHaveBeenCalledTimes(Math.ceil(1250 / MARKER_LOOKUP_CHUNK))
    for (const [args] of find.mock.calls) {
      expect(args.where.challenge.in.length).toBeLessThanOrEqual(MARKER_LOOKUP_CHUNK)
    }
    const queried = find.mock.calls.flatMap(([args]) => args.where.challenge.in)
    expect(new Set(queried).size).toBe(1250)
    const left = result.docs.flatMap((doc) => doc.sessions.map((session) => session.id))
    expect(left).toHaveLength(1250 - revoked.length)
    for (const sid of revoked) expect(left).not.toContain(sid)
  })

  it('fails closed when any lookup fails', async () => {
    const { req } = fakeReq(new Set(), 2)
    await expect(run(req, findResult(5, 250))).rejects.toThrow('too many SQL variables')
  })

  it('makes no lookup when the documents carry no sessions', async () => {
    const { find, req } = fakeReq(new Set())
    await run(req, { docs: [{ id: 1 }, { id: 2, sessions: [] }] })
    expect(find).not.toHaveBeenCalled()
  })
})
