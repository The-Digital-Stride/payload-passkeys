#!/usr/bin/env bash
# npm audit signatures, with one fallback for a stale CDN copy of a package's attestations.
#
# On GitHub's runners the check sometimes reports "<package> has attestations but no
# corresponding public key(s) can be found" (magic-string, caniuse-lite, @peculiar/x509, ...),
# while the same lockfile verifies cleanly elsewhere. Cause (2026-11-09): npm's CDN caches
# /-/npm/v1/attestations/<package> for a year (cache-control max-age=31557600), and the publish
# attestation is added a few seconds after a version appears. A CDN location that fetched in that
# window keeps the provenance-only copy, so pacote finds no attestation with a registry key id
# (pacote/lib/registry.js). Clearing npm's cache, waiting, query strings and no-cache request
# headers don't refresh it: retrying can't help.
#
# registry.npmjs.com is the same registry behind its own cache entries. npm verifies the default
# registry against the keys Sigstore's TUF repository distributes, but any other host against that
# host's /-/npm/v1/keys (npm/lib/utils/verify-signatures.js, setKeys). So the fallback runs only
# after scripts/registry-keys-match.mjs proves those keys are exactly the TUF ones the first run
# fetched, and then verifies every package again, not only the one that failed. It falls back only
# on that exact message, and only when this script's own requests see the symptom: no publish
# attestation in registry.npmjs.org's copy, one in registry.npmjs.com's. Anything else, such as a
# bad signature or an unknown registry key, fails at once.
#
# Known limits, accepted while npm's CDN is broken this way: npm audit signatures stops at its first
# error, so a second, different problem behind the stale copy is checked only against
# registry.npmjs.com; and npm fetches registry.npmjs.com's keys again itself, after the comparison,
# so a compromised registry.npmjs.com could show the comparison one set and npm another. Both need
# npm's own registry hosts to disagree in a crafted way. Report repeats to npm
# (github.com/npm/feedback) with the cache headers printed below; only npm can purge the copies.
set -uo pipefail

fallback=https://registry.npmjs.com

output="$(npm audit signatures 2>&1)"
status=$?
echo "$output"
if [ "$status" -eq 0 ]; then exit 0; fi
# Only the stale-copy symptom may fall back: the attestations message, not any other error with
# the same code (an unknown registry signature key raises EMISSINGSIGNATUREKEY too).
package="$(sed -nE 's/^npm error ([^ ]+) has attestations but no corresponding public key\(s\) can be found$/\1/p' <<<"$output")"
if [ -z "$package" ] || [ "$(wc -l <<<"$package")" -ne 1 ]; then exit "$status"; fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Evidence for the log, and the diagnosis the fallback depends on: each host's cache headers, its
# attestations for the package npm named, and how many are publish attestations (the ones with a
# registry key id). Prints that count last, or "none" when the fetch fails.
check_host() {
  echo "Attestations $1 returns for $package:" >&2
  if ! curl -fsS -D "$tmp/headers" -o "$tmp/body" "$1/-/npm/v1/attestations/$package"; then
    echo "  (fetch failed)" >&2
    echo none
    return
  fi
  grep -iE '^(age|cf-cache-status|cf-ray|date|last-modified):' "$tmp/headers" | sed 's/^/  /' >&2
  # shellcheck disable=SC2016 # the ${...} are JavaScript template literals, not shell
  node -e 'let n=0;try{for(const a of JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).attestations){const k=a.bundle.dsseEnvelope.signatures[0].keyid;if(k)n++;console.error(`  ${a.predicateType} keyid=${JSON.stringify(k)}`)}}catch(e){console.error(`  unreadable: ${e.message}`);n="none"}console.log(n)' "$tmp/body"
}
on_default="$(check_host https://registry.npmjs.org)"
on_fallback="$(check_host "$fallback")"
if [ "$on_default" != 0 ] || ! [[ "$on_fallback" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::Not the stale-CDN case (registry.npmjs.org: $on_default publish attestations, $fallback: $on_fallback). Not falling back."
  exit "$status"
fi

tuf_keys="$(npm config get cache)/_tuf/tuf-repo-cdn.sigstore.dev/targets/registry.npmjs.org%2Fkeys.json"
if [ ! -f "$tuf_keys" ]; then
  echo "::error::No TUF key list at $tuf_keys, so $fallback can't be checked. Not falling back."
  exit "$status"
fi
api_keys="$tmp/keys.json"
if ! curl -fsS "$fallback/-/npm/v1/keys" -o "$api_keys" ||
  ! node "$(dirname "$0")/registry-keys-match.mjs" "$tuf_keys" "$api_keys"; then
  echo "::error::$fallback's keys couldn't be confirmed against the TUF list. Not falling back."
  exit "$status"
fi

echo "::warning::npm's CDN served an incomplete attestations copy for ${package:-a package}; verifying everything again through $fallback, whose keys match the TUF list."
npm audit signatures --registry "$fallback"
