import { describe, expect, it } from 'vitest'

import { isWriteConflict, revokedSessionMarker } from '../../src/server/sessions.js'

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
