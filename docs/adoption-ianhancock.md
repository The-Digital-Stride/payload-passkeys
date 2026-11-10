# Adopting payload-passkeys on ianhancock.co.uk

Instructions for a later session working in `/Users/ianhancock/My Repos/ianhancock`. They are self-contained: you don't need this repository's plan to follow them, but `README.md` here is the plugin's user guide and worth reading first.

Written 2026-11-06 for `@the-digital-stride/payload-passkeys`, updated 2026-11-10 for 1.2.0, which is on npm.

## Rules for that session

Follow that repository's `CLAUDE.md`. In particular:

- Create a branch first: `passkeys-sign-in`, from an up-to-date `main`.
- Commit, never push. Ian pushes.
- The dev server is Ian's. Never start one and leave it running, and never run `pnpm build` while his is running.
- Use the `payload` skill for the Payload work, and check Payload behaviour against `node_modules`.
- UK English in anything a person reads.
- Nothing in this repository (payload-passkeys) changes as part of that work.

## Facts about that repository (as of 2026-11-06; check them again first)

- `src/payload.config.ts`:
  - sets no `serverURL` and no `csrf`;
  - sets `cors: [getServerSideURL()]` and `admin.user: Users.slug`;
  - uses `mongooseAdapter` with `MONGODB_URI` and a pinned `dbName`.
- `src/utilities/getURL.ts` `getServerSideURL()` returns, in order:
  1. `NEXT_PUBLIC_SERVER_URL`;
  2. `https://${VERCEL_PROJECT_PRODUCTION_URL}` (the production domain, even on preview builds);
  3. `http://localhost:3100`.
- `src/collections/Users/index.ts`: `auth: true`, a `name` field, `useAsTitle: 'name'`, all access `authenticated`. Sessions are on (Payload's default), which the plugin requires.
- Plugins are assembled in `src/plugins/index.ts`.
- Payload 3.90.2. `package.json` engines are `^18.20.2 || >=20.9.0`, with pnpm 11 and native build approvals in `pnpm-workspace.yaml` (`allowBuilds`). pnpm 11 reads its settings from `pnpm-workspace.yaml`, not `.npmrc`.
- Local development shares the production Atlas database, and the e2e suites use one throwaway user per spec file.

## Steps

### 1. Check the prerequisites

- The Vercel project's Node version is 22 or later (Settings → Build and Deployment). If the site later moves to Payload 3.92 or later, Payload itself needs Node `^22.23.4` or `>=24.22.1`.
- Change `engines.node` in `package.json` to `>=22.12.0`.
- Install the exact version: `pnpm add -E @the-digital-stride/payload-passkeys@1.2.0`.
- If `pnpm-workspace.yaml` sets `minimumReleaseAge`, the release must be older than that, or be listed in `minimumReleaseAgeExclude`.

### 2. Set `csrf` before anything else

Today the `csrf` list is empty (no `serverURL`, no `csrf`), so Payload accepts the admin session cookie from any origin. The plugin warns about this at boot. In `src/payload.config.ts` add:

```ts
csrf: [
  getServerSideURL(),
  ...(process.env.VERCEL_URL ? [`https://${process.env.VERCEL_URL}`] : []),
  ...(process.env.VERCEL_BRANCH_URL ? [`https://${process.env.VERCEL_BRANCH_URL}`] : []),
],
```

The preview entries keep the admin working on preview deployments, which today works only because the list is empty. Check the admin on a preview deployment before going further.

### 3. Add the plugin

In `src/plugins/index.ts`:

```ts
import { passkeysPlugin } from '@the-digital-stride/payload-passkeys'
import type { RateLimitHook } from '@the-digital-stride/payload-passkeys'
import { checkRateLimit } from '@vercel/firewall'

const rateLimit: RateLimitHook = async ({ action, key, req }) => {
  // The firewall exists only on Vercel; allow everything in local development.
  if (process.env.VERCEL !== '1') return true
  // `status` is anonymous, read-only and runs on every login-page view: don't count it.
  if (action === 'status') return true
  const { error, rateLimited } = await checkRateLimit('passkeys', {
    headers: req.headers,
    rateLimitKey: key,
    // No default timeout: a slow Firewall would hang the ceremony. A timeout rejects and the
    // plugin answers 429.
    timeout: 3000,
  })
  // error 'not-found' means no rule has the ID "passkeys": refuse rather than run unlimited.
  return !rateLimited && !error
}

// in the plugins array
passkeysPlugin({
  origins: [getServerSideURL()],
  rateLimit,
  rpID: new URL(getServerSideURL()).hostname,
  rpName: 'Bits & Blogs',
}),
```

- `rpID` and `origins` must be explicit because `serverURL` isn't set: without them the plugin refuses to start. If production is also served from a second address (for example `www.`), add that origin too; every origin must be the RP ID or under it.
- In production they resolve to the production domain. On preview builds they also resolve to the production domain (`VERCEL_PROJECT_PRODUCTION_URL`), so `*.vercel.app` previews show password sign-in only, with a short note in place of the button. That is by design.
- Locally they resolve to `localhost:3100`. Because local development shares the Atlas database, a passkey made locally is stored with RP ID `localhost` and shows as "Made for localhost" in the Passkeys section on the live site. Say so in the PR.
- Production needs `auth.cookies.secure: true` on the `users` collection: Payload's default is `false`, and the cookie follows that setting.
- Add `@vercel/firewall` as an exact dependency (`pnpm add -E @vercel/firewall`). Ian creates a Vercel WAF rule with the `@vercel/firewall` rate limit ID `passkeys` and a rate-limit action in the dashboard. Ask him once with AskUserQuestion: it is a dashboard step only he can take. Until the rule exists, the hook above refuses passkey requests (password sign-in is unaffected); without any hook the plugin logs a production warning instead.

### 4. Generate

```bash
pnpm payload generate:importmap
pnpm payload generate:types
```

(or that repository's own aliases for them). MongoDB needs no migration. At boot the plugin builds its three unique indexes on `passkey-challenge-uses`, `passkey-challenges` and `passkeys`; the Atlas database user needs `createIndex` (the `readWrite` role has it). Look for `passkeys: ready` in the log, and for any `passkeys: … unique index … is missing` error: without the index a challenge could be used twice.

The plugin adds a `passkeysManager` `ui` field and a hidden `passkeyUserHandle` field to `users`. Both are admin-only, which breaks that repository's rule that every field has a frontend use. Record them as an exception, the way `generatorRunId` is.

### 5. Document

In that repository's `CLAUDE.md`, under "Payload config", add a bullet covering:

- the plugin, where it is configured (`src/plugins/index.ts`), and the RP ID rule (passkeys belong to the production domain; changing `rpID` breaks them);
- that previews are password-only;
- the recovery command, `pnpm payload passkeys:reset --collection users --email <email>` (or `--id <id>`), which removes the user's passkeys and pending registrations and signs them out everywhere, leaving the password working;
- that the `passkeys`, `passkey-challenges` and `passkey-challenge-uses` collections belong to the plugin.

### 6. Test

- Ask Ian to restart his dev server.
- On `http://localhost:3100/admin`, sign in with the password. Expect the "Sign in faster with a passkey" prompt. Add a passkey (Touch ID), sign out, and sign in with **Sign in with a passkey**.
- Add `tests/e2e/passkeys.e2e.spec.ts`. Create the virtual authenticator in the page that runs the ceremony (a new page doesn't have it), and keep the test's origin in `origins` (here `getServerSideURL()`, which is `http://localhost:3100` locally). It uses its own throwaway user `passkeys-e2e@payloadcms.com` (that repository's convention: one user per spec file, created and deleted by the spec) and a CDP virtual authenticator, as in this repository's `test/e2e/passkeys.e2e.spec.ts` and `test/e2e/helpers.ts`. Cover: enrol, sign out, sign in with the button, remove. `afterAll` deletes the user; the plugin removes their passkeys with them.
- Run `pnpm lint`, `pnpm exec tsc --noEmit`, `pnpm test:int` and `pnpm test:e2e tests/e2e/passkeys.e2e.spec.ts`, after checking what owns port 3100.

### 7. Offboarding

Follow the README's "Offboarding" section: `refuseSignInUnless` to refuse disabled users, and `resetPasskeys` when someone is disabled. Ask Ian whether the site has a field that marks leavers before adding it. The site's database is MongoDB, which runs transactions only on a replica set (Atlas is one), so the README's guarantees for a disable that races a sign-in apply.

### 8. Ship

- Commit on the branch; Ian pushes.
- On the preview deployment, check that password sign-in works and that the note shows in place of the button.
- After the merge, check production: add a passkey and sign in with it.
- Run `pnpm payload passkeys:reset --collection users --email <throwaway user's email>` once against a throwaway user, to prove recovery works on Atlas.
