#!/usr/bin/env bash
# Applies the committed example migrations to an empty database, then asks Payload for a new
# migration with --skip-empty. Any file created means the plugin's schema drifted from the
# committed migrations. Leaves the working tree as it found it, pass or fail.
#
# Usage: bash scripts/check-migrations.sh postgres|sqlite
# Postgres: start it first with `docker compose -f dev/docker-compose.yml up -d postgres`.
set -euo pipefail

adapter="${1:-}"
case "$adapter" in
  postgres | sqlite) ;;
  *)
    echo "Usage: bash scripts/check-migrations.sh postgres|sqlite" >&2
    exit 2
    ;;
esac

cd "$(dirname "$0")/.."
dir="dev/migrations/$adapter"
if [ ! -f "$dir/index.ts" ]; then
  echo "No committed migrations in $dir." >&2
  exit 1
fi

# NODE_ENV=production: no schema push at connect and no `generate:types` child process.
export DATABASE_ADAPTER="$adapter" NODE_ENV=production PAYLOAD_MIGRATING=true
db_file="test/.tmp/check-migrations.db"
if [ "$adapter" = sqlite ]; then
  mkdir -p test/.tmp
  rm -f "$db_file"
  export DATABASE_URL="file:$(pwd)/$db_file"
fi

# Remember what was there, so only what this run creates is removed afterwards.
scratch="$(mktemp -d)"
ls -1 "$dir" | sort >"$scratch/before"
cp "$dir/index.ts" "$scratch/index.ts"
cleanup() {
  ls -1 "$dir" | sort >"$scratch/after"
  comm -13 "$scratch/before" "$scratch/after" | while read -r file; do rm -f "$dir/$file"; done
  cp "$scratch/index.ts" "$dir/index.ts"
  rm -rf "$scratch"
  if [ "$adapter" = sqlite ]; then rm -f "$db_file"; fi
}
trap cleanup EXIT

pnpm --silent dev:payload migrate:fresh --force-accept-warning
pnpm --silent dev:payload migrate:create drift-check --skip-empty

ls -1 "$dir" | sort >"$scratch/after"
created="$(comm -13 "$scratch/before" "$scratch/after")"
if [ -n "$created" ]; then
  echo "The plugin's schema changed: regenerate $dir and add a README upgrade note." >&2
  echo "Payload generated (removed again by this script):" >&2
  echo "$created" | sed 's/^/  /' >&2
  migration="$(echo "$created" | grep '\.ts$' | head -1 || true)"
  if [ -n "$migration" ]; then sed -n '1,40p' "$dir/$migration" >&2; fi
  exit 1
fi
echo "Migrations for $adapter are up to date."
