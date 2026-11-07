import { describe, expect, it } from 'vitest'

import { shouldRenderManager } from '../../src/components/PasskeysManagerField/shouldRender.js'

const props = (overrides: Record<string, unknown> = {}) =>
  ({
    collectionSlug: 'users',
    id: 1,
    operation: 'update',
    req: { user: { collection: 'users', id: 1 } },
    ...overrides,
  }) as never

describe('shouldRenderManager', () => {
  it('is true only on your own document', () => {
    expect(shouldRenderManager(props())).toBe(true)
    expect(shouldRenderManager(props({ id: '1' }))).toBe(true)
    expect(shouldRenderManager(props({ id: 2 }))).toBe(false)
    expect(shouldRenderManager(props({ id: undefined, operation: 'create' }))).toBe(false)
    expect(shouldRenderManager(props({ req: { user: { collection: 'customers', id: 1 } } }))).toBe(
      false,
    )
    expect(shouldRenderManager(props({ req: { user: null } }))).toBe(false)
  })
})
