// Usage: node scripts/registry-keys-match.mjs <tuf keys.json> <registry /-/npm/v1/keys json>
//
// Exits 0 only when the registry's keys API lists exactly the keys Sigstore's TUF repository
// distributes for registry.npmjs.org: the same key ids, key bytes and expiry dates. npm verifies
// the default registry against the TUF list, but any other registry host against that host's own
// keys API (npm/lib/utils/verify-signatures.js, setKeys), so scripts/audit-signatures.sh runs this
// before it trusts registry.npmjs.com. Node built-ins only.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const time = (value) => (value ? new Date(value).getTime() : null)

/** keyid -> { key, expires }, or a reason it can't be read consistently. */
const index = (entries, read) => {
  if (!Array.isArray(entries) || entries.length === 0) return { reason: 'no keys' }
  const keys = new Map()
  for (const entry of entries) {
    const { expires, id, key } = read(entry ?? {})
    if (typeof id !== 'string' || typeof key !== 'string' || !id || !key) {
      return { reason: 'a key without an id or key bytes' }
    }
    const seen = keys.get(id)
    if (seen && (seen.key !== key || seen.expires !== expires)) {
      return { reason: `${id} appears twice with different details` }
    }
    keys.set(id, { expires, key })
  }
  return { keys }
}

export const keysMatch = (tuf, api) => {
  const expected = index(tuf?.keys, (k) => ({
    expires: time(k.publicKey?.validFor?.end),
    id: k.keyId,
    key: k.publicKey?.rawBytes,
  }))
  if (expected.reason) return { ok: false, reason: `TUF list: ${expected.reason}` }
  const actual = index(api?.keys, (k) => ({ expires: time(k.expires), id: k.keyid, key: k.key }))
  if (actual.reason) return { ok: false, reason: `keys API: ${actual.reason}` }

  for (const id of new Set([...expected.keys.keys(), ...actual.keys.keys()])) {
    const want = expected.keys.get(id)
    const got = actual.keys.get(id)
    if (!want) return { ok: false, reason: `keys API has ${id}, which the TUF list doesn't` }
    if (!got) return { ok: false, reason: `keys API lacks ${id}` }
    if (want.key !== got.key) return { ok: false, reason: `${id} has different key bytes` }
    if (want.expires !== got.expires) return { ok: false, reason: `${id} has a different expiry` }
  }
  return { ok: true }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [tufFile, apiFile] = process.argv.slice(2)
  const result = keysMatch(
    JSON.parse(readFileSync(tufFile, 'utf8')),
    JSON.parse(readFileSync(apiFile, 'utf8')),
  )
  if (!result.ok) {
    console.error(`Registry keys don't match the TUF list: ${result.reason}`)
    process.exit(1)
  }
  console.log('Registry keys match the TUF list.')
}
