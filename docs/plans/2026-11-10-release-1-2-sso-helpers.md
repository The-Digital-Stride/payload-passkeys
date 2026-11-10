# Release 1.2.0: SSO host helpers and README fixes

**Goal:** fold back what tds-website (the first SSO host, PRs #209–#214 in `The-Digital-Stride/tds-website-2026`) had to build or learn around 1.1.0, so the next host doesn't repeat it: export two small safety helpers, and fix the README and adoption samples that would mislead.

**Branch:** `release-1-2-sso-helpers`. **Version:** 1.2.0 (minor: new exports). One release, docs and code together.

**Source of findings:** a Fable overseer comparison of the site against the plugin (2026-11-10), checked in code by the lead. Site files referenced below are on tds-website `origin/main` (`5cc006f2`).

## Decisions

**D1. Export `safeAdminRedirect` from the main entry and from `/client`.**
`src/shared/redirect.ts` is pure (only `payload/shared`), already unit-tested, and the site had to copy it (`src/app/api/auth/google/safeAdminRedirect.ts`) because it isn't exported. Signature unchanged: `safeAdminRedirect(redirectTo: unknown, adminRoute = '/admin'): string`. `/client` too, because a host's login button (a client component) builds the Google start URL from the page's `redirect`.
Plain: sites get the plugin's tested "stay inside the admin" check instead of writing their own.

**D2. Harden `safeAdminRedirect` with the site's encoded-character rule; length cap is opt-in.**
(a) Refuse a resolved pathname containing `%2f`, `%5c` or `%2e` (any case): no admin path needs them, and a server that decodes them later could resolve elsewhere. A host that percent-encodes a dot in a custom text ID loses the return path (falls back to the admin route), which is acceptable. (b) New optional third argument `{ maxLength?: number }`: input or result longer than `maxLength` returns the admin route. No cap by default, because the plugin's own flows store nothing in a cookie and a long filtered list URL should still return the admin to their place; a host that carries the path in an OAuth state cookie passes `{ maxLength: 1500 }`. The cap counts the input as given and the result as percent-encoded, so non-ASCII paths can hit it sooner (documented). The `#hash` is kept and counted. The function doesn't double-decode (`%252e%252e` passes, as today): tested and documented.
Signature: `safeAdminRedirect(redirectTo: unknown, adminRoute = '/admin', options?: { maxLength?: number }): string`.
Plain: odd encoded links fall back to the admin home page; sites that need a size limit can ask for one.

**D3. New export `refuseSignInUnless(isAllowed)`, a `CollectionBeforeLoginHook` factory.**
```ts
export type SignInAllowed = (user: Record<string, unknown>) => boolean | Promise<boolean>
export const refuseSignInUnless: (
  isAllowed: SignInAllowed,
  options?: { recheckTimeoutMs?: number }, // default 5000
) => CollectionBeforeLoginHook
```
Behaviour: (1) if `isAllowed(withoutSecrets(user))` is false, throw Payload's `UnauthorizedError(req.t)`; (2) re-read the user's committed record with `req.payload.db.findOne` **without `req`** (so outside the sign-in's transaction; verified on all three adapters), trash-filtered like `loadRawUser`; if it's gone or `isAllowed(withoutSecrets(stored))` is false, throw the same error; (3) otherwise return `user`. A throw in `isAllowed` or in `findOne` propagates, so the sign-in is refused (fails closed). The re-read is raced against `recheckTimeoutMs` (default 5,000 ms); on expiry it refuses. Reason: on Postgres the sign-in's transaction holds one pool connection and the re-read needs a second (`@payloadcms/drizzle/dist/utilities/getTransaction.js`: no `transactionID` → `adapter.drizzle`, the pool); with `pool.max: 1`, or a full pool, it would otherwise wait for ever (pg-pool's `connectionTimeoutMillis` defaults to 0). README: Postgres needs a pool of at least 3 (corrected in the build: the adapter keeps one connection itself, so `max: 1` cannot even boot). MongoDB and libsql are unaffected.
Shapes: the hook's `user` is the raw stored record (depth 0, no afterRead, no virtual fields) with `collection` and `_strategy` added; the re-read has neither. So both calls receive `{ ...withoutSecrets(record), collection: <slug> }`, the slug and `trash` setting taken from the hook's `collection` argument. Documented. The hook also covers Payload's reset-password flow (`resetPassword.js` runs beforeLogin). The predicate never receives `hash`, `salt`, `sessions` or the other fields `withoutSecrets` (`src/server/mintSession.ts`) strips, so a predicate that logs its argument can't leak them.
Why: Payload's login (`payload/dist/auth/operations/login.js`: findOne :151, initTransaction :193, addSessionToUser :225, resetLoginAttempts :276, beforeLogin :286) and the plugin's `mintSession` (same order) read the user first, then `addSessionToUser` writes **the whole record** back (`payload/dist/auth/sessions.js`, `updateOne` with `data: user`) **before** beforeLogin runs. So a "disabled" saved between that first read and the session write is overwritten with the stale value.
- **With transactions** (Postgres by default; SQLite only with `transactionOptions`; MongoDB only with a replica set, which the plugin's own test suite uses): the stale write is uncommitted, the re-read sees the committed "disabled", the hook refuses and the rollback undoes the stale write and the login-attempt reset. This is the case the hook exists for.
- **Without transactions** (SQLite by default, `db-sqlite/dist/index.js:100`; db-mongodb without a replica set, `connect.js:56-58`): the stale write is already committed when the hook runs, so the re-read sees the stale value. The hook then refuses only users disabled **before** the sign-in's first read; a disable that lands in the window is lost and the user stays signed in. Login attempts and lockout are also cleared before the hook runs. Documented plainly, with the advice: use transactions in production (replica set, or `transactionOptions`), and after disabling someone reload the record and check it held.
It covers Payload's own login, passkey sign-in and `signInVerifiedUser`, because all run the collection's `beforeLogin` hooks.
Plain: with transactions, a leaver disabled at the same moment they sign in is refused and stays disabled; without them, only an earlier disable is caught, and the README says so.

**D4. Not in the plugin (README recipes instead).**
Hiding `sessions` on afterRead for inactive users (relies on Payload's JWT strategy checking `user.sessions`), the afterChange `resetPasskeys` call, the Google `hd`/`email_verified`/state checks, the Vercel rate-limit settings, the login-button width, the CDP virtual-authenticator test helper. The site's account-approval model, Google linking, copy overrides and password clean-up script stay site-specific.
Plain: the plugin stays small; the README shows how.

**D5. README fixes** (`README.md`, samples pinned by `dev/readme-samples.ts` and `test/unit/readmeSamples.spec.ts`):
1. Rate limiting, Vercel sample: add `timeout: 3000` (`@vercel/firewall` 1.2.6 has no default timeout, so a slow Firewall hangs a ceremony; on timeout it rejects, and the plugin's fail-closed hook handling answers 429, which the README must say) and `if (action === 'status') return true` with the reason; move the `status` note from the SSO "Things to know" list here.
2. SSO callback sample: use `safeAdminRedirect` instead of the inline regex; delete the state cookie with `{ name: 'oauth_state', path: <the path it was set on> }` (a bare name writes `Path=/` and won't clear a narrower cookie); keep the constant-time `state` comparison but name the real controls on the state cookie: `HttpOnly`, `SameSite=Lax`, `Secure` in production, a short `maxAge`, deleted on use; if the return path rides in that cookie, pass `{ maxLength }`.
3. "Things to know": for Google, check the returned `hd` claim (the URL `hd` is only a hint) and `email_verified`; don't rely on the authorisation URL.
4. Offboarding sample: use `refuseSignInUnless`; run `resetPasskeys` whenever the save **sets** the field inactive (`'disabled' in data`), not only on the change, reading the value from `data` (the `select` gotcha folded in); state which adapters run transactions by default (Postgres yes; SQLite only with `transactionOptions`; MongoDB only with a replica set), so elsewhere `req` gives no rollback and a failed clean-up is retried by saving again.
5. Offboarding: add the afterRead `sessions: []` recipe for ending live sessions of an inactive user without deleting them, with the Payload reference (`payload/dist/auth/strategies/jwt.js`). Say that hiding is reversible (re-enabling brings unexpired sessions back unless `resetPasskeys` ran, which is why the recipe pairs them), and that the field it reads must not be `hidden: true` (hidden fields are stripped before collection afterRead hooks, so everyone would look active). Postgres pool of at least 3 for `refuseSignInUnless`.
6. Rewrite "Sign-in at the same moment" around `refuseSignInUnless`: what it guarantees with transactions, what it can't without them (D3), and **keep** "reload the user and check that the change held" for databases without transactions. Recommend transactions in production.
7. New "Testing" subsection: Playwright CDP virtual authenticator options; create it in the page that runs the ceremony; the test origin must be in `origins`.
8. Styling note: the sign-in block (`.passkeys-sign-in`) fills Payload's login column; scope a `max-width` to match other buttons.
9. Cookie settings bullet: production needs `auth.cookies.secure: true`.

**D6. Adoption doc fixes** (`docs/adoption-ianhancock.md`): 1.2.0 is on npm (drop "wait for a release" and "two weeks on 0.x"); rate-limit sample as D5.1; `auth.cookies.secure` for production; same-page CDP and `origins` note; an Offboarding step pointing to the README.

**D7. Also:** changeset (minor); `CLAUDE.md` status line is stale ("not released"); update it.

## Contract
- `src/index.ts`: add `export { safeAdminRedirect } from './shared/redirect.js'`, `export { refuseSignInUnless } from './server/refuseSignInUnless.js'`, and the `SignInAllowed` type.
- `src/exports/client.ts`: add `export { safeAdminRedirect } from '../shared/redirect.js'`.
- New `src/server/refuseSignInUnless.ts` (server-only; not reachable from `/client`; the import-boundary test must stay green).

## Builders and files
- **Builder A (Opus, code):** `src/shared/redirect.ts`, `src/server/refuseSignInUnless.ts`, `src/index.ts`, `src/exports/client.ts`, `src/types.ts` (the `SignInAllowed` type, if types live there), `test/unit/redirect.spec.ts`, new `test/int/refuseSignInUnless*.int.spec.ts`, new test configs under `test/configs/`, `dev/db.ts` (a `sqliteTransactions` option mapping to `transactionOptions: {}`), `dev/buildConfig.ts` (a `trash` option for a test config), and `dev/testHooks.ts` if needed.
- **Builder B (Sonnet, docs):** `README.md`, `dev/readme-samples.ts`, `dev/readme-samples.d.ts`, `docs/adoption-ianhancock.md`, `docs/design.md` (new decision entries for D2 and D3, in the style of D16/D17).
- **Lead:** this plan, `.changeset/*`, `CLAUDE.md`.

## Tests (tests first)
- Unit (redirect): `%2f`, `%2F`, `%5c`, `%2e` in the path → admin route; 1,501-char input → admin route; a 1,500-char valid path passes; existing cases still pass.
- Unit (redirect, more): `a%2Eb` in the path → admin route; `#hash` kept and counted toward `maxLength`; non-ASCII expansion (`/admin/` + 600 `é` with `maxLength: 1500` → admin route); double-encoded `/admin/%252e%252e/api` passes unchanged (pins "no double decode"); no `maxLength` → a 3,000-character admin path passes.
- Int contract, every adapter (`DATABASE_ADAPTER=mongo|postgres|sqlite`):
  - Payload REST login, passkey sign-in and `signInVerifiedUser` are each refused for a disallowed user and leave no new session.
  - **Stale object:** the hook is handed an allowed user object while the stored record is disallowed → refused.
  - The predicate never receives `hash`, `salt` or `sessions` (both calls).
  - A throwing `isAllowed` refuses; `db.findOne` stubbed to throw refuses and leaves no session.
  - A soft-deleted user (trash on) is refused.
- **Race seam** (from the Payload review): spy on `payload.db.findOne`; on the sign-in's first `users` read **with** `req` for the target ID, commit the disable with `payload.db.updateOne` **without** `req`, then return the stale doc. That puts the disable after the first read and before `initTransaction`, so `addSessionToUser` writes the stale record back. (A disable written from inside beforeLogin deadlocks on Postgres and SQLite: don't.) The predicate field is `name: 'Left'` through the existing `testHooks.beforeLogin` (`dev/buildConfig.ts`), so no schema change.
- **Race with transactions** on MongoDB (the suite's memory server is a replica set, `test/globalSetup.ts:20`), Postgres, and SQLite with `transactionOptions: {}` (new `test/configs/sqliteTransactions.ts`, `dev/db.ts` option): REST login, `signInVerifiedUser` and passkey sign-in each answer 401/refuse, the stored name stays `Left`, and no session is added.
- **Race without transactions** on default SQLite only: pins the documented limit (sign-in succeeds; the stale value is stored).
- **Pool:** Postgres with `pool.max: 1`: the sign-in is refused within `recheckTimeoutMs` (use a short value in the test), not hung.
- The `findOne`-throws stub throws only when `!args.req`.
- Redirect unit: `%2F` in the **query string** is kept (Payload qs-encodes the redirect it builds).
- Client boundary test still green; `readmeSamples.spec.ts` green.

## Gates
`pnpm typecheck`, `pnpm lint`, `pnpm test:unit`, `pnpm test:int` on mongo, postgres (docker compose) and sqlite, `pnpm build`, `pnpm check:package`. e2e only if the redirect change touches a flow e2e covers (it does: run `pnpm test:e2e`).

## Reviews
Plan: Fable security expert, then Payload CMS expert. Diff: the same two again.

## Pre-review outcomes
**Security (Fable, 2026-11-10).** Blocking: B1, the plan claimed the hook refuses without transactions; false, because `addSessionToUser` commits the stale whole-record write before beforeLogin (verified `login.js:225/286`, `sessions.js`), so D3 and D5.6 were rewritten. B2, SQLite runs no transactions unless `transactionOptions` is set (verified `db-sqlite/dist/index.js:100`), so the race tests were split into with and without. Should: S1 predicate gets `withoutSecrets(user)`; S2 `findOne` failure tested; S3 README says a Firewall timeout answers 429; S4 lockout cleared before the hook, documented. Nice: N1 state-cookie controls named; N2 length cap made opt-in (`maxLength`); N3 extra redirect tests. Verified clean: `findOne` without `req` is outside the transaction on all three adapters; Google `hd`/`email_verified`; `auth.cookies.secure` default; the `status` exemption; the afterRead recipe.

**Payload CMS (Opus, 2026-11-10).** Blocking: B1 Postgres pool deadlock (verified `getTransaction.js`), so the re-read gets a timeout and the README a pool minimum; B2 the proposed seam deadlocked, replaced by the `findOne` spy seam; B3 the Mongo test server is a replica set (verified `test/globalSetup.ts:20`), so Mongo moves to "with transactions" and the no-transaction limit is pinned on default SQLite. Should: S1 both predicate calls get the same shape with `collection`; S2 file list (`dev/db.ts`, `dev/buildConfig.ts`, test configs, narrow stub); S3 the afterRead recipe is reversible and needs a non-hidden field. Nice: `%2F` in the query kept; reset-password also runs beforeLogin. Verified clean: hook type, raw `user`, `'disabled' in data`, no re-entry, no clash with `hideRevokedSessions`, minor bump, no `package.json` exports change.

## Build notes
- Postgres needs a pool of **3**, not 2. `@payloadcms/db-postgres/dist/connect.js` holds one connection from boot, so `max: 1` can't even start. The pool test uses `max: 2` (refused within the timeout), and a `max: 3` spec proves sign-in works.
- A refused passkey sign-in answers 400 `sign_in_failed`, the endpoint's uniform failure, not 401.
- The soft-deleted and stale-object cases call the hook directly. Payload's login and `loadRawUser` already skip trashed users, so a full sign-in never reaches the hook with one.

## Review outcomes (diff)
**Security (Fable).** Nothing blocking. 42 redirect bypass inputs were probed and none escaped. Fixed:
- S1: the README now says the predicate sees the host's own `hidden` fields, so don't log it whole.
- N1: the timer-clearing test now pins the hook's own handle. It was proven to fail with the clean-up removed.
- N2: the race wording was narrowed. The plan-review findings B1, B2, S1–S4 and N1–N3 are all addressed.

**Payload CMS (Opus).** Nothing blocking. Fixed:
- S1: the cut-off for "refused and stays saved" is the session write, not the hook's check. After that write, Postgres waits and keeps the disable; MongoDB fails the save with a write conflict (reproduced on a replica set). README, D19 and the JSDoc now say so.
- N1: a read-replica note was added.
- N2: without transactions, a refused password reset has already changed the password. Documented.
- N3: the race tests now assert the predicate saw `['Test User', 'Left']` (or the stale name twice without transactions), so they fail if they stop testing the race.

All plan-review findings are addressed.
