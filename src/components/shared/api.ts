'use client'

export type ApiReply = {
  data: Record<string, unknown> & { error?: string }
  ok: boolean
  status: number
}
export type Api = (path: string, body?: unknown) => Promise<ApiReply>

/** POSTs JSON to /api/<collection>/passkeys/... on this origin, with the session cookie. */
export const createApi =
  (apiRoute: string, collectionSlug: string): Api =>
  async (path, body = {}) => {
    try {
      const res = await fetch(`${apiRoute}/${collectionSlug}${path}`, {
        body: JSON.stringify(body),
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
      })
      let data: ApiReply['data'] = {}
      try {
        data = (await res.json()) as ApiReply['data']
      } catch {
        data = {}
      }
      return { data, ok: res.ok, status: res.status }
    } catch {
      return { data: { error: 'network' }, ok: false, status: 0 }
    }
  }
