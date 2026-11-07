#!/usr/bin/env bash
# npm audit signatures, retried only on EMISSINGSIGNATUREKEY.
#
# On GitHub's runners the check intermittently reports "<package> has attestations but no
# corresponding public key(s) can be found" for a different package each run (magic-string,
# @peculiar/x509, ...), while the same lockfile verifies cleanly elsewhere, with a fresh cache too.
# That is the registry's attestation lookup, not a bad signature: an invalid or missing registry
# signature fails with a different code on every attempt and is never retried here.
set -uo pipefail

attempts=3
for attempt in $(seq 1 "$attempts"); do
  output="$(npm audit signatures 2>&1)"
  status=$?
  echo "$output"
  if [ "$status" -eq 0 ]; then exit 0; fi
  if ! grep -q 'EMISSINGSIGNATUREKEY' <<<"$output" || [ "$attempt" -eq "$attempts" ]; then
    exit "$status"
  fi
  echo "::warning::npm audit signatures could not find an attestation key (attempt $attempt of $attempts); retrying."
  sleep $((attempt * 10))
done
