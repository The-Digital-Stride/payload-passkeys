import type { PayloadRequest } from 'payload'

import { describe, expect, it, vi } from 'vitest'

import { logEvent } from '../../src/server/logging.js'

describe('logEvent', () => {
  it('still logs a failure, without the IP, when the clientIp resolver throws', () => {
    const warn = vi.fn()
    const req = { payload: { logger: { warn } } } as unknown as PayloadRequest
    const clientIp = () => {
      throw new Error('no proxy header')
    }
    logEvent(req, { clientIp, logging: { ip: 'full' } }, 'passkeys.sign_in_failed', {
      collection: 'users',
      reason: 'bad_signature',
    })
    expect(warn).toHaveBeenCalledWith({
      collection: 'users',
      event: 'passkeys.sign_in_failed',
      msg: 'passkeys.sign_in_failed',
      reason: 'bad_signature',
    })
  })
})
