#!/usr/bin/env bash
# The release workflow's version script (release.yml, `version` job): applies the patch the
# `changes` job made with `changeset version`, after checking it does only what a version bump does.
#
# The `changes` job runs dependency code (@changesets/cli and the changelog generator), so its patch
# is untrusted; this job holds the release App's key and installs nothing. The patch is refused, and
# the version PR not updated, unless:
#   - it touches only package.json, CHANGELOG.md and .changeset/ markdown files and pre.json;
#   - it creates or deletes only plain files (no rename, mode change or link), and doesn't create
#     .changeset/pre.json (only `changeset pre enter` does);
#   - CHANGELOG.md only gains lines and the changesets only lose them;
#   - package.json differs in `version` alone.
# Reading the PR's diff before merging (docs/release-setup.md, Releasing) is still the check on
# what the changelog says.
set -euo pipefail

patch="${RUNNER_TEMP:?}/version/version.patch"
fail() {
  echo "::error::The version patch $1"
  exit 1
}

[ -s "$patch" ] || fail "is empty, but changesets/action found pending changesets."

# --numstat prints "added<TAB>deleted<TAB>path" per file. git quotes unusual paths and shows a
# rename as "old => new"; neither matches the allowlist. Each git command runs on its own, so a git
# error stops the script instead of passing as an empty list.
numstat="$(git apply --numstat "$patch")"
summary="$(git apply --summary "$patch")"

allowed='^(package\.json|CHANGELOG\.md|\.changeset/pre\.json|\.changeset/[A-Za-z0-9_-]+\.md)$'
refused="$(cut -f3- <<<"$numstat" | grep -Ev "$allowed" || true)"
[ -z "$refused" ] || fail "touches files a version bump never touches: $refused"

odd="$(grep -Ev '^ (create|delete) mode 100644 ' <<<"$summary" || true)"
[ -z "$odd" ] || fail "renames, changes a mode or adds a link: $odd"
if grep -q ' create mode [0-7]* \.changeset/pre\.json$' <<<"$summary"; then
  fail "creates .changeset/pre.json, which only \`changeset pre enter\` does."
fi

# Binary changes show "-" for both counts, which fails both tests below.
while IFS=$'\t' read -r added deleted path; do
  case "$path" in
    CHANGELOG.md) [ "$deleted" = 0 ] || fail "deletes lines from CHANGELOG.md." ;;
    .changeset/pre.json) ;;
    .changeset/*) [ "$added" = 0 ] || fail "adds lines to $path." ;;
  esac
done <<<"$numstat"

git apply "$patch"

# Compared as parsed JSON, so only the values count, not the formatting.
before="$(git show HEAD:package.json | jq -S 'del(.version)')"
after="$(jq -S 'del(.version)' package.json)"
if [ "$before" != "$after" ]; then
  diff <(echo "$before") <(echo "$after") || true
  fail "changes package.json beyond its version."
fi

git status --short
