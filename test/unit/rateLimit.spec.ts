import type { PayloadRequest } from 'payload'

import { describe, expect, it, vi } from 'vitest'

import { allowedByRateLimit } from '../../src/server/rateLimit.js'

const request = () => {
  const error = vi.fn()
  return { error, req: { payload: { logger: { error } } } as unknown as PayloadRequest }
}

describe('allowedByRateLimit', () => {
  it('asks the hook, keyed by user when there is one', async () => {
    const { req } = request()
    const rateLimit = vi.fn(async () => true as const)
    const allowed = await allowedByRateLimit({
      action: 'delete',
      collectionSlug: 'users',
      options: { clientIp: () => '203.0.113.9', rateLimit },
      req,
      userId: 7,
    })
    expect(allowed).toBe(true)
    expect(rateLimit).toHaveBeenCalledWith(
      expect.objectContaining({ ip: '203.0.113.9', key: 'users:7', userId: 7 }),
    )
  })

  it('refuses, like a throwing rateLimit hook, when the clientIp resolver throws', async () => {
    const { error, req } = request()
    const rateLimit = vi.fn(async () => true as const)
    const allowed = await allowedByRateLimit({
      action: 'sign-in.options',
      collectionSlug: 'users',
      options: {
        clientIp: () => {
          throw new Error('no proxy header')
        },
        rateLimit,
      },
      req,
    })
    expect(allowed).toBe(false)
    expect(rateLimit).not.toHaveBeenCalled()
    expect(error).toHaveBeenCalledWith(
      expect.objectContaining({ msg: expect.stringContaining('clientIp') }),
    )
  })

  it('refuses when the rateLimit hook throws or answers anything but true', async () => {
    for (const rateLimit of [
      vi.fn(async () => {
        throw new Error('redis down')
      }),
      vi.fn(async () => 'yes' as never),
    ]) {
      const { req } = request()
      const allowed = await allowedByRateLimit({
        action: 'delete',
        collectionSlug: 'users',
        options: { clientIp: () => null, rateLimit },
        req,
      })
      expect(allowed).toBe(false)
    }
  })
})
