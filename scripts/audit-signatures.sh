#!/usr/bin/env bash
# npm audit signatures, retried only on EMISSINGSIGNATUREKEY, with a fresh fetch each time.
#
# On GitHub's runners the check intermittently reports "<package> has attestations but no
# corresponding public key(s) can be found" for a different package each run (magic-string,
# @peculiar/x509, ...), while the same lockfile verifies cleanly elsewhere, with a fresh cache too.
# pacote raises it when none of the package's attestation bundles carries a registry key id
# (pacote/lib/registry.js), that is, when the attestations response came back without npm's
# publish attestation. That response goes through npm's cache, so a retry alone reuses it: each
# retry clears the cache first. A bad or missing registry signature fails with a different code on
# every attempt and is never retried here.
set -uo pipefail

attempts=3
for attempt in $(seq 1 "$attempts"); do
  output="$(npm audit signatures 2>&1)"
  status=$?
  echo "$output"
  if [ "$status" -eq 0 ]; then exit 0; fi
  if ! grep -q 'EMISSINGSIGNATUREKEY' <<<"$output"; then exit "$status"; fi

  # Evidence for the log: what the registry returned for the package npm named.
  package="$(sed -nE 's/^npm error ([^ ]+) has attestations but no corresponding.*/\1/p' <<<"$output" | head -1)"
  if [ -n "$package" ]; then
    echo "Attestations the registry returns for $package:"
    # shellcheck disable=SC2016 # the ${...} are JavaScript template literals, not shell
    curl -fsS "https://registry.npmjs.org/-/npm/v1/attestations/$package" |
      node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{for(const a of JSON.parse(s).attestations)console.log(`  ${a.predicateType} keyid=${JSON.stringify(a.bundle.dsseEnvelope.signatures[0].keyid)}`)}catch(e){console.log(`  unreadable: ${e.message}`)}})' ||
      echo "  (fetch failed)"
  fi

  if [ "$attempt" -eq "$attempts" ]; then exit "$status"; fi
  echo "::warning::npm audit signatures could not match an attestation to a registry key (attempt $attempt of $attempts); clearing npm's cache and retrying."
  npm cache clean --force >/dev/null 2>&1 || true
  sleep $((attempt * 10))
done
