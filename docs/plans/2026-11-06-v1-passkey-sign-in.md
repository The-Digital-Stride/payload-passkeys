# v1 Passkey Sign-in Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship `@the-digital-stride/payload-passkeys` 1.0.0: admins of any Payload `>=3.90 <4` site (MongoDB, Postgres or SQLite) can register, rename and remove passkeys and sign in to the admin with one, alongside email and password, with a hardened CI and release pipeline, then adopt it on ianhancock.co.uk.

**Architecture:** A plain Payload plugin function adds three hidden collections (`passkeys`, `passkey-challenges`, `passkey-challenge-uses`), a hidden user-handle field and a `ui` field to each configured auth collection, collection endpoints under `/api/<slug>/passkeys/*`, and three admin components loaded by import path. After a verified WebAuthn ceremony, `src/server/mintSession.ts` (the only module that touches Payload's undocumented auth helpers) mints an ordinary Payload session, so Payload's own JWT strategy, refresh, logout and revocation keep working. SimpleWebAuthn 14 does the WebAuthn cryptography; a test enforces that nothing server-side reaches the client bundle.

**Tech Stack:** TypeScript (ESM, NodeNext), Payload 3.90.2 to 3.93.x, Next.js 16, React 19, `@simplewebauthn/server` 14.0.3 and `@simplewebauthn/browser` 14.0.0 (pinned exactly), Vitest 4 (unit and integration), mongodb-memory-server, `@payloadcms/db-mongodb`, `-db-sqlite`, `-db-postgres`, Playwright with a CDP virtual authenticator, swc and tsc for the build, Changesets, GitHub Actions, npm trusted publishing. pnpm 11, Node 22+.

> **Status (2026-11-06):** Tasks 1 to 43 and 45's instructions are done on branch `v1-passkey-sign-in`; Task 44 is the developer's. Where the code differs from a task below, the code is the truth: see the "Implemented as" notes under the tasks and `docs/design.md` section 13. Throughout, the stored slug field on `passkeys` and `passkey-challenges` is **`authCollection`**, not `collection` (Mongoose reserves `collection`); read every `collection: { equals … }` on those collections and every `row.collection` as `authCollection`.

---

## Verified facts

Everything below was checked on 2026-11-06 against the installed Payload 3.90.2 source in `/Users/ianhancock/My Repos/ianhancock/node_modules/.pnpm/payload@3.90.2_graphql@16.14.2_typescript@5.9.3/node_modules/payload/dist` (written `PL/`), `@payloadcms/ui@3.90.2` (`UI/`), `@payloadcms/next@3.90.2` (`NX/`), the published `@simplewebauthn/server@14.0.3` and `@simplewebauthn/browser@14.0.0` tarballs, `@payloadcms/db-sqlite`, `-db-postgres` and `-drizzle` 3.93.0 tarballs, and the `templates/plugin` folder of `payloadcms/payload` on the `3.x` branch. Where a fact changes a decision in `docs/design.md`, the design section is named.

### Q1. Re-checking the password for the fresh-session rule

- **`authenticateLocalStrategy` is not exported.** It lives in `PL/auth/strategies/local/authenticate.js` (`authenticateLocalStrategy({ doc, password }): Promise<{ doc, shouldUpdatePasswordHash } | null>`), but `payload`'s `exports` map (`.`, `./internal`, `./node`, `./shared`, `./i18n/*`, `./migrations`) blocks deep imports and no entry re-exports it. The hash format (`pbkdf2-sha256-v1:` prefix, 600 000 iterations, legacy 25 000) is private to `generatePasswordSaltHash.js` and changes in 3.93 (`auth.passwordHashIterations`), so reimplementing it is ruled out.
- **The safe path is `loginOperation`**, exported from `payload` (`PL/index.d.ts:502`): `loginOperation<TSlug>({ collection: Collection, data: { email?, username?, password }, depth?, overrideAccess?, req: PayloadRequest, showHiddenFields? }): Promise<{ exp?: number; token?: string; user? }>`. It returns `token` even when `removeTokenFromResponses` is set (only the endpoint and `payload.login` strip it). It enforces `checkLoginPermission` (lockout), calls `incrementLoginAttempts` on a wrong password, re-checks the lock inside the transaction, runs `beforeLogin` and `afterLogin`, and creates a new session whose `createdAt` is now (`PL/auth/operations/login.js:165-331`).
- **Decision (security review H1, accepted):** `POST /passkeys/reauth { password }` runs `loginOperation` with the identifier taken from `req.user` on the server, sets the new session's cookie, revokes the old `sid`, and is rate limited with action `reauth` keyed by user id. The new session is the fresh one. Task 8 (module) and Task 18 (endpoint).
- **Implemented as:** `reauthenticate` also refuses (`wrong_account`) when the account `loginOperation` signed in isn't the session's (with `loginWithUsername` and email login both on, Payload matches `email = x OR username = x`), and ends that stray session. It builds the response before revoking the old session, and logs a failed revoke instead of throwing.

### Q2. A `type: 'ui'` field on the account page

- **It renders.** `NX/views/Account/index.js` builds form state with `buildFormState({ ..., renderAllFields: true, operation: 'update' })` and renders `EditView`, so every field in the auth collection, `ui` fields included, renders on `/admin/account` as on the user edit view.
- **Props** (`UI/forms/fieldSchemasToFormState/renderField.js`): every `admin.components` key on a `ui` field goes through `RenderServerComponent`.
  - Client components get `clientProps` only: `{ field, path, permissions, readOnly, schemaPath }`, plus the component's own `clientProps`.
  - Server components get those plus `serverProps`: `{ id, clientField, clientFieldSchemaMap, collectionSlug, data, field, fieldSchemaMap, formState, i18n, operation, payload, permissions, preferences, req, siblingData, user, value }`.
  - On the account page `id === req.user.id` and `collectionSlug === admin.user`. On another user's edit view `id` is theirs; on create, `operation === 'create'` and `id` is undefined.
  - The types are `UIFieldServerProps` and `UIFieldClientProps`, exported from `payload` (`PL/admin/types.d.ts:70`). `ServerComponentProps.user` is documented as "with field read access applied; use `req.user` for access checks", so the RSC wrapper compares `req.user`.
- **Decision:** `PasskeysManagerField` (RSC, `./rsc`) renders `null` unless `operation === 'update'`, `req.user.collection === collectionSlug` and `String(req.user.id) === String(id)`. Only then does it render the client `PasskeysManager`. Task 28.

### Q3. Session helpers, hooks and transactions in 3.90.2

| Helper | Import from | Signature |
|---|---|---|
| `addSessionToUser` | `payload/shared` | `({ collectionConfig, payload, req, user }) => Promise<{ sid?: string }>`. Returns `sid` only when `auth.useSessions`; writes the **whole** `user` object back with `db.updateOne`; sets `user.updatedAt = null` first (`PL/auth/sessions.js`) |
| `getFieldsToSign` | `payload` | `({ collectionConfig, email, sid?, user }) => Record<string, unknown>`. `saveToJWT` fields plus `id`, `collection` (from `collectionConfig.slug`), `email`, `sid` |
| `jwtSign` | `payload` | `({ fieldsToSign, secret, tokenExpiration }) => Promise<{ exp: number; token: string }>`. HS256 with protected header `authVersion: JWT_AUTH_VERSION` (also exported from `payload`) |
| `generatePayloadCookie` | `payload/shared` | `({ collectionAuthConfig, cookiePrefix, returnCookieAsObject?, token }) => string`. Name `${cookiePrefix}-token`, `HttpOnly`, `Path=/`, `Expires` = now + `tokenExpiration`, `SameSite`/`Secure`/`Domain` from `auth.cookies` |
| `checkLoginPermission` | `payload` | `({ loggingInWithUsername?, req, user }) => void`. Throws `AuthenticationError` for a missing user and `LockedAuth` when `lockUntil` is in the future. **Not used** by passkey sign-in (review M5) |
| `resetLoginAttempts` | `payload` | `({ collection: SanitizedCollectionConfig, doc, payload, req }) => Promise<void>`. A partial `db.updateOne` of `{ lockUntil: null, loginAttempts: 0 }`, skipped when there is nothing to reset |
| `initTransaction` | `payload` | `(req) => Promise<boolean>`. `true` means "you started it, you commit it". Resolves `false` when the adapter has no transactions |
| `commitTransaction`, `killTransaction` | `payload` | `(req) => Promise<void>` |
| `revokeSession`, `isUserLocked`, `applyUserReadAccess`, `buildBeforeOperation` | **not public** | `revokeSession` and `isUserLocked` are not exported. `applyUserReadAccess` is only in `payload/internal`, documented as unstable. `buildBeforeOperation` is not exported (review L8) |

- **How core orders a login** (`loginOperation`):
  1. `beforeOperation`.
  2. `db.findOne` loads the raw user.
  3. `checkLoginPermission`, then the password check, then the `_verified` check.
  4. `initTransaction`.
  5. `addSessionToUser`, then `getFieldsToSign`.
  6. `resetLoginAttempts` (when `maxLoginAttempts > 0`).
  7. `beforeLogin` hooks: `user = (await hook({ collection, context, req, user })) || user`.
  8. `jwtSign`, then `req.user = user`.
  9. `afterLogin` hooks: `({ collection, context, req, token, user })`.
  10. `applyUserReadAccess`, then `afterOperation`.
  11. `commitTransaction`.
  12. On any throw: `revokeSession(sid)`, then `killTransaction`.

  `mintSession` repeats steps 4 to 12 in this order without the password. The design's §3 puts `resetLoginAttempts` last, but core runs it before `beforeLogin`, and the plan follows core.
- **Adapters and transactions:**
  - Mongo starts a transaction only on a replica set (`@payloadcms/db-mongodb/dist/connect.js`: it falls back to `defaultBeginTransaction()` when `replicaSet` is unset).
  - SQLite has no transactions unless `transactionOptions` is passed (`db-sqlite/dist/index.js:103`).
  - Postgres always has transactions.
- **Revocation:**
  - Logout removes `req.user._sid`, or every session with `?allSessions=true` (`PL/auth/operations/logout.js`).
  - **A password change keeps the session that made the change** when the user changes their own password (`PL/collections/operations/utilities/update.js:300-304`). A change from any other session, or by an admin, revokes the minted session. The contract test locks in both behaviours.
- **`/me` returns `sessions` to the owner.** The field's read access is `user?.id === doc?.id` (`PL/auth/baseFields/sessions.js`), and `/me` reads with `overrideAccess: false` as the owner. So "build the response like `/me`" (review M1) is not enough by itself. `toResponseUser` also strips a denylist (Task 7).
- `payload.findByID` accepts `user`, which replaces `req.user` (`PL/utilities/createLocalReq.js:91`).
- `refresh` changes only `expiresAt` on the session (`PL/auth/operations/refresh.js:55`), so `createdAt` measures time since sign-in.

### Q4. How the admin consumes a login response

- `useAuth().setUser(res: UserWithToken | null)` (`UI/providers/Auth/index.d.ts`). The shape is `{ exp: number; token?: string; refreshedToken?: string; user }`.
  - `exp` is the **epoch-seconds** JWT expiry. The comment there says "seconds until expiration", but the code does `setTokenExpirationMs(exp * 1000)`.
  - `setUser` arms the stay-logged-in reminder and the forced logout from `exp`.
- **The stock `LoginForm`** (`NX/views/Login/LoginForm/index.js`):
  - Its `<Form>` has `action = formatAdminURL({ apiRoute, path: '/<admin.user>/login' })`, `onSuccess = (data) => setUser(data)` and `redirect = getSafeRedirect({ fallbackTo: adminRoute, redirectTo: searchParams.redirect })`.
  - After success, `Form` runs `startRouteTransition(() => router.push(redirect))`, with `useRouter` from `next/navigation.js` (`UI/forms/Form/index.js:5,365`).
  - `adminRoute` is `config.routes.admin`, default `/admin`.
  - `getSafeRedirect({ allowAbsoluteUrls?, fallbackTo?, redirectTo })` is exported from `payload/shared`. It accepts only same-origin relative paths: no `//`, `/\`, `/%2F`, control characters, `/javascript:` or `/http`. It does not limit the result to admin paths, so the plugin adds the admin-prefix check (review L5).
- **`LoginView`** (`NX/views/Login/index.js`) renders `beforeLogin`, then `LoginForm` (unless `disableLocalStrategy`), then `afterLogin`. The slots are RSC slots with `{ i18n, locale, params, payload, permissions, searchParams, user }`, outside the `<Form>`.
- **Design correction (§7):** `@payloadcms/ui` 3.90.2 does **not** export `useRouter`, `usePathname` or `PayloadLink`, and its `useSearchParams` is `@deprecated` in favour of `next/navigation`. The plugin imports `useRouter` and `useSearchParams` from `next/navigation.js` in exactly one module (`src/components/shared/navigation.ts`), so the v4 port changes one file.

### Q5. The official plugin template (`templates/plugin`, branch `3.x`, fetched 2026-11-06)

- **Layout:** `src/{index.ts, exports/client.ts, exports/rsc.ts, components/, endpoints/}`. `dev/` is a Next app containing `payload.config.ts`, `next.config.mjs`, `tsconfig.json` (path aliases to `../src`), `app/(payload)/{layout.tsx, custom.scss, admin/[[...segments]]/{page,not-found}.tsx, admin/importMap.js, api/[...slug]/route.ts, api/graphql/route.ts, api/graphql-playground/route.ts}`, `helpers/{credentials,testEmailAdapter}.ts`, `seed.ts`, `int.spec.ts` and `e2e.spec.ts`. The root holds `.swcrc`, `tsconfig.json`, `vitest.config.js`, `playwright.config.js`, `eslint.config.js` and `.prettierrc.json`.
- **package.json:**
  - `"type": "module"`, and `exports` pointing at `./src/*.ts` for development.
  - `publishConfig.exports` pointing at `./dist/*.js` with `.d.ts`; `files: ["dist"]`.
  - Scripts: `build` = `pnpm copyfiles && pnpm build:types && pnpm build:swc`; `build:swc` = `swc ./src -d ./dist --config-file .swcrc --strip-leading-paths`; `build:types` = `tsc --outDir dist --rootDir ./src`; `copyfiles` = `copyfiles -u 1 "src/**/*.{html,css,scss,ttf,woff,woff2,eot,svg,jpg,png,json}" dist/`; `dev` = `next dev dev --turbo`; `dev:payload` = `cross-env PAYLOAD_CONFIG_PATH=./dev/payload.config.ts payload`; `dev:generate-importmap`, `dev:generate-types`.
  - Engines: `node ^22.23.4 || >=24.22.1`, `pnpm ^9 || ^10 || ^11`.
  - Dev dependency pins: payload and `@payloadcms/*` 3.93.0, next 16.3.3, react 19.2.6, typescript 5.7.3, vitest 4.0.18, `@playwright/test` 1.63.0, mongodb-memory-server 10.1.4, `@swc/cli` 0.6.0.
- **.swcrc:** `jsc.target esnext`, TypeScript parser with `tsx: true`, React `runtime: automatic`, `module.type es6`, source maps on.
- **tsconfig:** `module`/`moduleResolution` NodeNext, `emitDeclarationOnly`, `composite`, `strict`, `jsx: react-jsx`, `lib` DOM + ES2022.
- **Dev config:**
  - When `NODE_ENV === 'test'`, `dev/payload.config.ts` starts `MongoMemoryReplSet` itself.
  - `admin.importMap.baseDir` is set to `dev/`.
  - `next.config.mjs` adds a webpack `extensionAlias` (`.js` → `.ts/.tsx`) and `serverExternalPackages: ['mongodb-memory-server']`, then `withPayload(nextConfig, { devBundleServerPackages: false })`.
  - `vitest.config.js` calls `loadEnv(path.resolve(dirname, './dev'))` from `payload/node` and uses `vite-tsconfig-paths`.
  - The Playwright `webServer` runs `pnpm dev` against `http://localhost:3000/admin`.
- **Changes made here:**
  - Start the memory server in a Vitest `globalSetup`, not in the config, so one replica set serves every file.
  - Add SQLite and Postgres adapters, chosen by `DATABASE_ADAPTER`.
  - Put specs in `test/`, not `dev/`.
  - Set peer ranges instead of the template's `^3.93.0`.

### Q6. A software authenticator for integration tests

- **Maintained helpers:**
  - `nid-webauthn-emulator` (0.2.17, MIT, about 6.3k downloads a week, single maintainer) is a whole browser-side emulator. It is 0.x and does not expose the knobs the rejection matrix needs (UP, UV, BE and BS per ceremony, an explicit counter, a wrong `rpIdHash`, a bad signature).
  - `webauthn-emulator` (1.0.2) depends on `cbor` and `tldts`.
- **Decision:** write `test/helpers/softAuthenticator.ts` (about 230 lines, complete in Task 17). It uses WebCrypto ES256 and `isoCBOR` / `isoBase64URL` from `@simplewebauthn/server/helpers`, which are already a dependency.
- **Verified in a scratch project with `@simplewebauthn/server@14.0.3` on Node 22.22.2:**
  - Registration verifies with `aaguid`, `credentialDeviceType` and `credentialBackedUp` correct.
  - An assertion verifies, and its `userHandle` round-trips.
  - Each override fails where it should:
    - UV off: "User verification required".
    - Bad signature: `verified: false`.
    - Wrong origin: "Unexpected authentication response origin".
    - Wrong RP ID: "Unexpected RP ID hash".
    - Wrong type: "Unexpected authentication response type".
  - BE=0 gives `singleDevice`.
  - Passing `counter: 0` to the library returns the authenticator's real `newCounter`.
  - Verifying against a throwaway dummy key returns `verified: false` in under 1 ms.
- ES256 signatures from WebCrypto are raw `r||s` and must be DER-encoded: SimpleWebAuthn's `unwrapEC2Signature` parses ASN.1. The helper does this.
- **Playwright CDP** (`ChromeDevTools/devtools-protocol` `WebAuthn.pdl`):
  - `WebAuthn.enable`.
  - `WebAuthn.addVirtualAuthenticator({ options: { protocol: 'ctap2', ctap2Version?, transport: 'internal', hasResidentKey, hasUserVerification, isUserVerified, automaticPresenceSimulation, defaultBackupEligibility, defaultBackupState } })` returns `{ authenticatorId }`.
  - Also `getCredentials`, `removeCredential` and `setResponseOverrideBits({ isBadUV, isBadUP, isBogusSignature })`.

### Q7. Database setup for integration tests in a plugin repo

- **MongoDB:**
  - Start `MongoMemoryReplSet.create({ replSet: { count: 1, storageEngine: 'wiredTiger' } })` in `globalSetup`, so transactions are on.
  - Pass `mongooseAdapter({ ensureIndexes: true, url })`. Without `ensureIndexes` the unique index that replay protection depends on may not exist yet (`connect.js` builds indexes only when set).
- **SQLite:** `sqliteAdapter({ client: { url: 'file:/abs/path.db' } })`. No transactions by default.
- **Postgres:** `postgresAdapter({ pool: { connectionString } })` against a `postgres:17` service container in CI, or `dev/docker-compose.yml` locally.
- **Schema push and reset:**
  - Both SQL adapters push the schema at connect when `NODE_ENV !== 'production'` and `PAYLOAD_MIGRATING !== 'true'` (`db-sqlite/dist/connect.js:50`, `db-postgres/dist/connect.js:110`). On a fresh database there are no data-loss prompts.
  - All three adapters honour `PAYLOAD_DROP_DATABASE=true` at connect.
  - Run test files one at a time (`fileParallelism: false`, `pool: 'forks'`) and set `PAYLOAD_DROP_DATABASE=true`, so each file boots onto an empty database.
- **Calling the REST API in-process:** `handleEndpoints({ config, request })`, exported from `payload` (`PL/utilities/handleEndpoints.d.ts`), runs the whole REST stack: auth strategies, CSRF in `extractJWT`, plugin endpoints and core `/login`, `/me`, `/refresh-token`, `/logout`. It needs no Next server. The test client (Task 3) wraps it with a cookie jar.
- **Migrations:** `payload migrate:create --skip-empty` is supported (`PL/bin/migrate.js:30`). It drives the "example migrations generate cleanly" check (Task 35).

### Other facts the plan depends on

- **Collection endpoints come before core auth endpoints** (`PL/collections/config/sanitize.js`), so every plugin path stays under `/passkeys/`. A collection with `endpoints: false` cannot host them. `resolveOptions` throws for that.
- **`addDataAndFileToRequest`** parses JSON only when `Content-Type` before `;` is exactly `application/json`. It parses `multipart/*` too and lifts a `_payload` field into `req.data` (`PL/utilities/addDataAndFileToRequest.js`). That is why review M4 requires JSON. **Implemented as:** the plugin doesn't call it. `readJsonBody` (`src/server/http.ts`) applies the same `application/json` test, reads the stream itself and stops past 64 KB (Payload's parser reads the whole body, and `Content-Length` is only a hint), then sets `req.data` and `req.json`.
- **`extractJWT`** accepts the cookie from any `Origin` when `config.csrf` is empty (`PL/auth/extractJWT.js`). Sanitize appends `serverURL` to `csrf` (`PL/config/sanitize.js:341`).
- **Duplicate keys are reported, not swallowed:**
  - The Mongo adapter maps duplicate-key error 11000 to a `ValidationError` (`db-mongodb/dist/utilities/handleError.js:34`).
  - Mongo `db.deleteOne` is `findOneAndDelete` (atomic).
  - Drizzle `deleteOne` is select, then `findFirst`, then delete: not atomic (review M3).
  - The plan consumes challenges with a unique insert and treats any insert error as a replay.
- **Unique fields on Mongo:** a `unique` field that is not `required` becomes a **sparse** unique index (`db-mongodb/dist/models/buildSchema.js:15-19`). Sparse indexes still index explicit `null`s. So the plan keeps `passkeyUserHandle` **not unique**: it is never queried, and it is 512 random bits.
- **Translations do not fall back to English.** `@payloadcms/translations` `initTFunction` merges `config.translations[language]` over the built-in strings for that language only, and returns the key when one is missing. **Design correction (§8):** the plugin copies its English `passkeys` namespace into every language in `i18n.supportedLanguages` (and any language the host translates), under the host's own overrides. Task 22.
- `config.admin.user` defaults at sanitize to the first auth collection; otherwise Payload pushes its own `users` collection after plugins run (`PL/config/sanitize.js:57-60`). The plugin resolves `admin.user ?? first auth collection` and throws if there is none.
- **Payload's `config.bin`** (`[{ key, scriptPath }]`, `PL/config/types.d.ts:931`) gives `payload <key>`, which loads `.env`, finds the host config and calls `script(config)` (`PL/bin/index.js:91-108`). **Design correction (§6):** the recovery CLI is `pnpm payload passkeys:reset --collection users --email x`, run in the host project, not a separate package `bin` that would have to find the host config itself.
- **SimpleWebAuthn 14.0.3:**
  - The `server` `engines` field says `>=20.0.0`, while the changelog says Node 22. The plan supports Node 22+.
  - It ships ESM and CJS; `exports` are `.` and `./helpers`.
  - `generateRegistrationOptions` and `generateAuthenticationOptions` treat a **string** `challenge` as UTF-8. The plan never passes one, so the library makes 32 random bytes (43 base64url characters).
  - The default `timeout` is 60 000, so the plan passes 300 000.
  - `requireResidentKey` is derived from `residentKey: 'required'`.
  - `verifyAuthenticationResponse` throws on `(counter > 0 || credential.counter > 0) && counter <= credential.counter`. The plan passes `counter: 0` and applies its own policy (review M7).
  - The library never compares the backup flags with the stored record.
- **`@simplewebauthn/browser@14.0.0`** exports:
  - `startRegistration({ optionsJSON, useAutoRegister? })` and `startAuthentication({ optionsJSON, useBrowserAutofill?, verifyBrowserAutofillInput? })`.
  - `sendSignal({ signalName: 'unknownCredential', rpID, credentialID } | { signalName: 'allAcceptedCredentials', rpID, userID, allAcceptedCredentialIDs } | { signalName: 'currentUserDetails', rpID, userID, userName, userDisplayName? })`, which throws when the browser lacks the method.
  - `browserSupportsWebAuthn()`, `platformAuthenticatorIsAvailable()`, `getBrowserCapabilities()` (`'supported' | 'unsupported' | 'unknown'` per key) and `WebAuthnError` (codes include `ERROR_CEREMONY_ABORTED`).
- **The community AAGUID list** is at `passkeydeveloper/passkey-authenticator-aaguids` commit `d53c0f358deeec6ba23d6c6e1f25f32ce45c22f9`, with 67 entries. AAGUIDs for the 20 common providers were confirmed from it (Task 23).
- **GitHub Action SHAs** (latest releases, 2026-11-06):

  | Action | Version | SHA |
  |---|---|---|
  | `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
  | `actions/setup-node` | v7.1.0 | `949feb2413d6458794dcd2491c4babbbce0c15c1` |
  | `pnpm/action-setup` | v6.1.1 | `73e46992e05b19abd31f2f3c20e0e7370d762115` |
  | `github/codeql-action` | v4.39.3 | `33d7b85da1a04171e211befe2c739303b9a4c066` |
  | `changesets/action` | v2.1.2 | `ae32849d5ba541f9ae29e40e22a623bc13562f51` |
  | `actions/upload-artifact` | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |

  Re-check them on the day.
- **Release tooling (checked 2026-11-06):**
  - npm documents trusted publishing for `npm publish` only (npm 11.5.1 or later). No source confirms OIDC support in `pnpm publish`, which `changeset publish` would call in a pnpm repo. So the release publishes with `npm publish` (Task 43), using npm 11.21.2 (latest 11.x; 12.2.2 is the newest).
  - `npm audit signatures` (npm 10.9.7) works on a pnpm-installed tree.
  - `@vercel/firewall` 1.2.6: `checkRateLimit(rateLimitId, { firewallHostForDevelopment?, rateLimitKey?, headers?, request?, timeout? }): Promise<{ rateLimited: boolean; error?: 'not-found' | 'blocked' }>`.
  - `@upstash/ratelimit` 2.2.0. `publint` 0.3.25. `@arethetypeswrong/cli` 0.18.5.
- **The AAGUID list:**
  - `aaguid.json` at the pinned commit has SHA-256 `2975a91ab5d24878bab9c7d4dc2341408cd013052a7a936921ca6117f551f075` and 67 entries.
  - The repository has **no licence file**, and its README marks the lists deprecated: no submissions from 1 November 2026, `{}` from 6 January 2027, archived 6 July 2027.
  - The icons are vendor logos, 0.6 to 19.7 KB each as data URIs. So the plan vendors names only (Task 23).
- **MongoDB indexes:** the adapter connects with `autoIndex: true` (`db-mongodb/dist/connect.js:15`), so Mongoose builds indexes in the background after boot. It awaits them only with `ensureIndexes: true` (`connect.js:67`). The plugin calls `createIndexes()` on its own models in `onInit` and checks that the unique index exists (Task 25).
- **Payload `extractJWT`** reads the `Authorization` header before the cookie. A JWT sent as a header therefore authenticates as `local-jwt` with a `sid`. `requireSignedIn` also requires the session cookie and no `Authorization` header, so only the browser session can manage passkeys (review L2, Task 14).
- **`useAuth` in 3.90.2** still exposes `tokenExpirationMs` (`UI/providers/Auth/index.d.ts:55`). v1 uses only `setUser`. The 3.91 `authSession` change matters in phase 2.
- **npm versions:**
  - `payload` latest is 3.93.0 and beta is 4.0.0-beta.7. The released 3.9x versions are 3.90.0 to 3.90.2, 3.91.0, 3.92.0, 3.92.1 and 3.93.0.
  - npm trusted publishing needs npm >= 11.5.1, but Node 22 ships npm 10, so the release job upgrades npm.

### Security review coverage (scratchpad `security-review.md`, all accepted)

| Finding | Covered by tasks |
|---|---|
| H1 re-auth is `loginOperation`, rotates session, rate limited `reauth` | 8, 18 |
| H2 lock ticket (phase 2) | phase 2 plan, M1 there |
| H3 `collection` text on rows (stored as `authCollection`), slug check first, `and[user.relationTo, user.value]`, colliding-ID test | 13, 20, 21, 32 |
| H4 `useSessions: false` throws | 11 |
| M1 response user via `findByID` as `/me`, plus denylist; secrets scan test | 7, 34 |
| M2 global anonymous cap, one sign-in challenge per browser key, prod warning, x-forwarded-for docs | 15, 20, 25, 38 |
| M3 unique-insert consume, parallel double-verify on 3 adapters | 15, 33 |
| M4 JSON only, Origin in `origins` else `Sec-Fetch-Site: same-origin`; config warn/throw | 11, 14, 25, 34 |
| M5 passkey sign-in ignores `lockUntil`, logs, resets attempts | 7, 20 |
| M6 CLI empties sessions; "Also sign out everywhere else" | 21, 24, 28 |
| M7 counter policy (`counter: 0` to library, own policy, `singleDevice`, device-type change refused, `backedUp` updated) | 16, 20 |
| M8 overlay rules (phase 2) | phase 2 plan |
| M9 config-time RP ID/origin checks, boot log, `status` detail only to signed-in users | 10, 11, 21, 25 |
| L1 `logging.ip`, no IP on success, README privacy note | 14, 38 |
| L2 signed-in endpoints need `_strategy === 'local-jwt'` and `_sid` | 14, 34 |
| L3 `graphQL: false`, `maxDepth: 0` | 13 |
| L4 handle made in `register/options`, copied to row `userHandle`, compared with row; refuse `credProps.rk === false` | 18, 19, 20 |
| L5 `getSafeRedirect` plus admin prefix, and no `//` or `/\` after dot segments resolve | 12 |
| L6 dummy verify on unknown credential | 16, 20 |
| L7 cookie security from configured origin's scheme, per-ceremony name, `Path=/`, no `Domain`, `Max-Age=300` | 14 |
| L8 document skipped `before/afterOperation`, `onSignIn` hook | 7, 38 |
| L9 exact SimpleWebAuthn pins, `minimumReleaseAge`, client dependency graph test, SHA-pinned actions, CODEOWNERS, `npm audit signatures` | 1, 4, 39, 40 |

### Design points this plan changes or settles (to fold into `docs/design.md`)

1. **§3 fields, `passkeyUserHandle`:** **not** `unique`. It is not queried, and Mongo's sparse unique index collides on explicit nulls. Each passkey row carries its own `userHandle` (L4).
2. **§3 challenges:** `user` is stored as `userId` (text) plus `collection` (text; built as `authCollection`), not a relationship. The challenge also stores `userHandle`. A third collection, `passkey-challenge-uses` (unique `challenge`), makes consumption atomic (M3).
3. **§3 passkeys access:** `delete` is `false` through the REST API as well, so all deletion goes through the guarded `/passkeys/delete` endpoint (M4). The design said "the collection's own DELETE also works". Read stays owner-only.
4. **§3 endpoints:** add `POST /passkeys/reauth` (H1). `status` takes POST with JSON like the others, skips the `Origin` allowlist (it reports a mismatch), and returns `{ available }` to anonymous callers (M9).
5. **§3 sign-in step 2 (`checkLoginPermission`):** replaced by the M5 rule. Step 8 (`resetLoginAttempts`) runs before `beforeLogin`, as in core.
6. **§4.4:** "Don't ask again" is localStorage only, per collection and user id. "After a password sign-in" is the first admin page view in a browser session while the user has no passkeys; a user with none must have signed in with the password.
7. **§6 recovery CLI:** `pnpm payload passkeys:reset --collection <slug> --email <email>` through `config.bin`. It deletes the user's passkeys and empties `sessions` (M6).
8. **§7:** router hooks come from `next/navigation.js` behind one module (see Q4). `@payloadcms/next` is **not** a peer in v1, because nothing imports it; it returns in phase 2 if a template is used.
9. **§8:** translations are copied into every supported language, because Payload does not fall back (see above).
10. **Options:** `lock` is not accepted in v1 (YAGNI; it arrives in phase 2). New options:
    - `freshSessionMinutes` (10)
    - `limits.passkeysPerUser` (20)
    - `limits.anonymousChallenges` (500)
    - `logging.ip` (`'truncated'`)
    - `onSignIn`
11. **§6 "no response contains `userHandle`" versus §4.1 step 8:** `signalAllAcceptedCredentials` needs the WebAuthn user ID. `status` returns it, as `signalUserId`, to its signed-in owner only. It appears in no other response. `status` also returns the owner's passkeys, so the manager makes one request and never queries the `passkeys` collection.
12. **§4.3 provider icons:** names only in v1 (the AAGUID list has no licence, and the icons are vendor logos); a generic passkey icon instead. Pre-1.0 decision.
13. **§3 Origin check:** applied to the anonymous ceremony endpoints too, not only the signed-in ones (all but `status`). Browsers always send `Origin` on a `POST` fetch, and this keeps other sites' visitors from filling the anonymous-challenge cap.
14. **§3 signed-in endpoints:** besides `local-jwt` and a `sid`, they require the session cookie and refuse an `Authorization` header. Otherwise a JWT sent as a header passes as `local-jwt`.
15. **§4.1 step 4 cookie names:** one per ceremony type **and collection** (`__Host-payload-passkeys-auth-users`), so two configured collections never overwrite each other's browser key.
16. **§10 release:** `npm publish` from a small script instead of `changeset publish` (see "Release tooling"). It is still versioned by Changesets.
17. **§3 MongoDB:** the plugin builds its own indexes at boot, so replay protection doesn't depend on the host setting `ensureIndexes`.

---

## Conventions for every task

- Repo root is `/Users/ianhancock/My Repos/payload-passkeys`. Every path below is relative to it.
- **Prettier:** single quotes, no semicolons, trailing commas, 100-character lines. Run `pnpm lint:fix` before each commit.
- **Imports:** relative imports end in `.js` (NodeNext). Type-only imports use `import type`.
- **Spelling:** UK English in every string a person sees (copy, errors shown to admins, README). US spelling is fine in code and logs.
- **Commits:** conventional commits. Commit, never push. Each task ends with the exact `git add` and message.
- **Tests:** `pnpm test:unit <file>` runs unit tests; `pnpm test:int <file>` runs integration tests on MongoDB. Prefix `DATABASE_ADAPTER=sqlite` or `DATABASE_ADAPTER=postgres DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/payload_passkeys` for the others.
- **Postgres locally:** `docker compose -f dev/docker-compose.yml up -d postgres`.

---

## Milestone M0: scaffold

End state: the package builds, the dev app boots on MongoDB, SQLite and Postgres, the test harness can call the REST API in-process, and the client-boundary test guards the tree from the first line of component code.

### Task 1: Package scaffold from the plugin template

> **Implemented as (2026-11-06):** there is no `.npmrc`. pnpm 11 reads only auth settings from `.npmrc`, so `engineStrict: true` and `saveExact: true` (and `shamefullyHoist`) live in `pnpm-workspace.yaml` beside `minimumReleaseAge` and `allowBuilds`. Read Step 2's `.npmrc` and the `git add … .npmrc` in Step 6 accordingly.

**Files:**
- Create: `package.json`, `pnpm-workspace.yaml`, `.npmrc`, `tsconfig.json`, `.swcrc`, `.prettierrc.json`, `eslint.config.js`, `LICENSE`, `src/index.ts`, `src/exports/client.ts`, `src/exports/rsc.ts`
- Modify: `.gitignore`

**Step 1: Write `package.json`.**

```json
{
  "name": "@the-digital-stride/payload-passkeys",
  "version": "0.0.0",
  "description": "Passkey (WebAuthn) sign-in for the Payload CMS admin, alongside email and password.",
  "license": "MIT",
  "type": "module",
  "keywords": ["payload", "payload-plugin", "passkeys", "webauthn"],
  "repository": { "type": "git", "url": "git+https://github.com/The-Digital-Stride/payload-passkeys.git" },
  "sideEffects": ["*.css"],
  "exports": {
    ".": { "import": "./src/index.ts", "types": "./src/index.ts", "default": "./src/index.ts" },
    "./client": { "import": "./src/exports/client.ts", "types": "./src/exports/client.ts", "default": "./src/exports/client.ts" },
    "./rsc": { "import": "./src/exports/rsc.ts", "types": "./src/exports/rsc.ts", "default": "./src/exports/rsc.ts" }
  },
  "main": "./src/index.ts",
  "types": "./src/index.ts",
  "files": ["dist", "LICENSE", "README.md", "SECURITY.md"],
  "scripts": {
    "build": "pnpm clean && pnpm copyfiles && pnpm build:types && pnpm build:swc",
    "build:aaguids": "node scripts/build-aaguids.mjs",
    "build:swc": "swc ./src -d ./dist --config-file .swcrc --strip-leading-paths",
    "build:types": "tsc --outDir dist --rootDir ./src",
    "changeset": "changeset",
    "clean": "rimraf dist \"*.tsbuildinfo\"",
    "copyfiles": "copyfiles -u 1 \"src/**/*.{css,json,svg}\" dist/",
    "dev": "next dev dev --turbo",
    "dev:generate-importmap": "pnpm dev:payload generate:importmap",
    "dev:generate-types": "pnpm dev:payload generate:types",
    "dev:payload": "cross-env PAYLOAD_CONFIG_PATH=./dev/payload.config.ts payload",
    "lint": "eslint .",
    "lint:fix": "eslint . --fix && prettier --write .",
    "prepublishOnly": "pnpm build",
    "release": "changeset publish",
    "test": "pnpm test:unit && pnpm test:int && pnpm test:e2e",
    "test:e2e": "playwright test",
    "test:int": "vitest run --project int",
    "test:unit": "vitest run --project unit",
    "typecheck": "tsc --noEmit -p dev/tsconfig.json"
  },
  "dependencies": {
    "@simplewebauthn/browser": "14.0.0",
    "@simplewebauthn/server": "14.0.3"
  },
  "peerDependencies": {
    "@payloadcms/ui": ">=3.90.0 <4",
    "next": ">=15.4.8 <17",
    "payload": ">=3.90.0 <4",
    "react": "^19.0.0",
    "react-dom": "^19.0.0"
  },
  "devDependencies": {
    "@changesets/cli": "3.0.3",
    "@payloadcms/db-mongodb": "3.93.0",
    "@payloadcms/db-postgres": "3.93.0",
    "@payloadcms/db-sqlite": "3.93.0",
    "@payloadcms/eslint-config": "3.28.0",
    "@payloadcms/next": "3.93.0",
    "@payloadcms/ui": "3.93.0",
    "@playwright/test": "1.63.0",
    "@swc-node/register": "1.10.9",
    "@swc/cli": "0.6.0",
    "@types/node": "22.19.9",
    "@types/react": "19.2.14",
    "@types/react-dom": "19.2.3",
    "copyfiles": "2.4.1",
    "cross-env": "7.0.3",
    "eslint": "9.23.0",
    "graphql": "16.8.1",
    "mongodb-memory-server": "10.1.4",
    "next": "16.3.3",
    "payload": "3.93.0",
    "prettier": "3.4.2",
    "react": "19.2.6",
    "react-dom": "19.2.6",
    "rimraf": "6.0.1",
    "typescript": "5.7.3",
    "vite-tsconfig-paths": "6.0.5",
    "vitest": "4.0.18"
  },
  "engines": { "node": ">=22.12.0", "pnpm": ">=11" },
  "packageManager": "pnpm@11.0.8",
  "publishConfig": {
    "access": "public",
    "provenance": true,
    "exports": {
      ".": { "import": "./dist/index.js", "types": "./dist/index.d.ts", "default": "./dist/index.js" },
      "./client": { "import": "./dist/exports/client.js", "types": "./dist/exports/client.d.ts", "default": "./dist/exports/client.js" },
      "./rsc": { "import": "./dist/exports/rsc.js", "types": "./dist/exports/rsc.d.ts", "default": "./dist/exports/rsc.js" }
    },
    "main": "./dist/index.js",
    "types": "./dist/index.d.ts"
  }
}
```

The two SimpleWebAuthn versions are exact on purpose (review L9). Bump them by hand, after reading the changelog.

**Step 2: Write `pnpm-workspace.yaml` and `.npmrc`.**

```yaml
packages:
  - '.'

# Wait a week before installing any newly published version (review L9). Minutes.
minimumReleaseAge: 10080

allowBuilds:
  esbuild: true
  mongodb-memory-server: true
  unrs-resolver: true
```

`.npmrc`:

```
engine-strict=true
save-exact=true
```

**Step 3: Copy the build config from the template.** Copy `.swcrc` and `.prettierrc.json` byte for byte from Verified facts Q5. Then write `tsconfig.json`:

```json
{
  "compilerOptions": {
    "baseUrl": ".",
    "lib": ["DOM", "DOM.Iterable", "ES2023"],
    "rootDir": "./",
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "esModuleInterop": true,
    "module": "NodeNext",
    "moduleResolution": "nodenext",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "react-jsx",
    "incremental": true,
    "emitDeclarationOnly": true,
    "target": "ES2022",
    "composite": true
  },
  "include": ["./src/**/*.ts", "./src/**/*.tsx"]
}
```

**Step 4: Write `eslint.config.js`.** Copy it from the template (Verified facts Q5). Add `'**/dev/app/(payload)/**'`, `'**/test/.tmp/**'` and `'**/*.generated.ts'` to `defaultESLintIgnores`, and add `'test/**/*.ts'` and `'dev/**/*.ts'` to `projectService.allowDefaultProject`.

**Step 5: Write the source stubs.**

`src/index.ts`:

```ts
import type { Config } from 'payload'

export type PasskeysPluginOptions = Record<string, never>

export const passkeysPlugin =
  (_options: PasskeysPluginOptions = {}) =>
  (config: Config): Config =>
    config
```

`src/exports/client.ts` and `src/exports/rsc.ts` each contain `export {}`.

**Step 6: Append to `.gitignore`, and add `LICENSE`.** Append these lines to `.gitignore`:

```
dev/media/
dev/*.db
test/.tmp/
*.tsbuildinfo
```

Create `LICENSE` with the MIT text, "Copyright (c) 2026 The Digital Stride".

**Step 7: Install and build.**

Run `pnpm install && pnpm build`. Expected: `dist/index.js`, `dist/index.d.ts` and `dist/exports/{client,rsc}.js` exist, with no errors.

**Step 8: Commit.**

```bash
git add package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc tsconfig.json .swcrc .prettierrc.json eslint.config.js .gitignore LICENSE src
git commit -m "chore: scaffold the plugin package from Payload's plugin template"
```

### Task 2: Dev app on three adapters

**Files:**
- Create:
  - `dev/next.config.mjs`, `dev/tsconfig.json`, `dev/.env.example`, `dev/docker-compose.yml`
  - `dev/db.ts`, `dev/testHooks.ts`, `dev/helpers/testEmailAdapter.ts`, `dev/seed.ts`
  - `dev/buildConfig.ts`, `dev/payload.config.ts`
  - `dev/app/(payload)/...`, copied from the template
- Test: none yet (Task 3 adds the smoke test)

**Step 1: Copy the template's app files.** Copy `dev/app/(payload)/` and `dev/helpers/testEmailAdapter.ts` from `templates/plugin` on `3.x` unchanged:

```
gh api "repos/payloadcms/payload/contents/templates/plugin/dev/app/(payload)/layout.tsx?ref=3.x" --jq .content | base64 -d
```

Do the same for `custom.scss`, `admin/[[...segments]]/page.tsx`, `admin/[[...segments]]/not-found.tsx`, `admin/importMap.js`, `api/[...slug]/route.ts`, `api/graphql/route.ts` and `api/graphql-playground/route.ts`.

**Step 2: Write `dev/next.config.mjs`.** Copy the template's, and add `allowedDevOrigins: ['127.0.0.1']` (the e2e preview-host test loads the admin from `http://127.0.0.1:3000`). Write `dev/tsconfig.json` as the template's, with these changes:
- `paths` maps `@the-digital-stride/payload-passkeys` (and `/client`, `/rsc`) to `../src/index.ts`, `../src/exports/client.ts` and `../src/exports/rsc.ts`.
- Add `"../test/**/*.ts"` and `"../scripts/**/*.ts"` to `include`.

**Step 3: Write `dev/db.ts`.**

```ts
import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { postgresAdapter } from '@payloadcms/db-postgres'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import path from 'path'
import { fileURLToPath } from 'url'

const dirname = path.dirname(fileURLToPath(import.meta.url))

export type AdapterName = 'mongo' | 'postgres' | 'sqlite'

export const adapterName = (): AdapterName => {
  const value = process.env.DATABASE_ADAPTER ?? 'mongo'
  if (value === 'mongo' || value === 'postgres' || value === 'sqlite') return value
  throw new Error(`DATABASE_ADAPTER must be mongo, postgres or sqlite, not "${value}"`)
}

export const databaseAdapter = () => {
  const url = process.env.DATABASE_URL
  switch (adapterName()) {
    case 'mongo':
      // ensureIndexes: the unique index on passkey-challenge-uses is the replay guard (M3).
      return mongooseAdapter({ ensureIndexes: true, url: url ?? 'mongodb://127.0.0.1/payload-passkeys' })
    case 'postgres':
      return postgresAdapter({
        migrationDir: path.resolve(dirname, 'migrations/postgres'),
        pool: { connectionString: url ?? 'postgres://postgres:postgres@127.0.0.1:5432/payload_passkeys' },
      })
    case 'sqlite':
      return sqliteAdapter({
        client: { url: url ?? `file:${path.resolve(dirname, 'dev.db')}` },
        migrationDir: path.resolve(dirname, 'migrations/sqlite'),
      })
  }
}
```

**Step 4: Write `dev/docker-compose.yml`.** It runs `postgres:17` on port 5432 with `POSTGRES_PASSWORD=postgres` and `POSTGRES_DB=payload_passkeys`.

**Step 5: Write `dev/testHooks.ts`.** Integration tests flip these switches; in the dev app they stay null.

```ts
type Hook = ((args: Record<string, unknown>) => unknown) | null

export const testHooks = {
  afterLogin: null as Hook,
  beforeLogin: null as Hook,
  onSignIn: null as Hook,
  reset() {
    this.afterLogin = null
    this.beforeLogin = null
    this.onSignIn = null
  },
}
```

**Step 6: Write `dev/buildConfig.ts`.** It holds two variants:
- `single`: only `users`, which logs in to the admin.
- `multi`: `users`, plus `customers`, a second auth collection with `verify: true` and `removeTokenFromResponses: true`.

```ts
import type { CollectionConfig, Config } from 'payload'

import { buildConfig } from 'payload'
import path from 'path'
import { fileURLToPath } from 'url'

import type { PasskeysPluginOptions } from '../src/index.js'

import { passkeysPlugin } from '../src/index.js'
import { databaseAdapter } from './db.js'
import { testEmailAdapter } from './helpers/testEmailAdapter.js'
import { seed } from './seed.js'
import { testHooks } from './testHooks.js'

const dirname = path.dirname(fileURLToPath(import.meta.url))
export const SERVER_URL = process.env.PAYLOAD_PUBLIC_SERVER_URL ?? 'http://localhost:3000'

const hookFields = {
  hooks: {
    afterLogin: [(args: Record<string, unknown>) => testHooks.afterLogin?.(args) as undefined],
    beforeLogin: [(args: Record<string, unknown>) => testHooks.beforeLogin?.(args) as undefined],
  },
}

const users: CollectionConfig = {
  slug: 'users',
  admin: { useAsTitle: 'name' },
  auth: { lockTime: 600_000, maxLoginAttempts: 5, useAPIKey: true },
  fields: [{ name: 'name', type: 'text' }],
  ...hookFields,
}

const customers: CollectionConfig = {
  slug: 'customers',
  admin: { useAsTitle: 'email' },
  auth: { removeTokenFromResponses: true, verify: true },
  fields: [],
  ...hookFields,
}

export const buildDevConfig = ({
  plugin = {},
  variant = 'single',
}: { plugin?: PasskeysPluginOptions; variant?: 'multi' | 'single' } = {}) =>
  buildConfig({
    admin: { importMap: { baseDir: path.resolve(dirname) }, user: 'users' },
    collections: variant === 'multi' ? [users, customers] : [users],
    // 127.0.0.1 stands in for a preview host: same app, not under the RP ID (Tasks 21 and 36).
    csrf: [SERVER_URL, 'http://127.0.0.1:3000'],
    db: databaseAdapter(),
    email: testEmailAdapter,
    onInit: async (payload) => {
      if (process.env.NODE_ENV !== 'test') await seed(payload)
    },
    plugins: [
      passkeysPlugin({
        collections: variant === 'multi' ? ['users', 'customers'] : ['users'],
        onSignIn: (args) => testHooks.onSignIn?.(args as Record<string, unknown>) as undefined,
        ...plugin,
      }),
    ],
    secret: process.env.PAYLOAD_SECRET ?? 'dev-only-secret-change-me',
    serverURL: SERVER_URL,
    typescript: { outputFile: path.resolve(dirname, 'payload-types.ts') },
  } satisfies Config)
```

Until Task 11 exists, `passkeysPlugin`'s options are typed `Record<string, never>`. Leave `onSignIn` commented out until then.

**Step 7: Write `dev/payload.config.ts` and `dev/seed.ts`.**

```ts
import { buildDevConfig } from './buildConfig.js'

export default buildDevConfig({ variant: 'single' })
```

`dev/seed.ts` creates `dev@payloadcms.com` with password `test` and name `Dev` if no user has that email. Copy the template's `dev/helpers/credentials.ts` shape into `dev/helpers/credentials.ts`.

**Step 8: Boot each adapter.**
1. Run `pnpm dev`, open `http://localhost:3000/admin` and sign in as `dev@payloadcms.com` / `test`. Expected: the dashboard.
2. Stop the server.
3. Run `DATABASE_ADAPTER=sqlite pnpm dev` and repeat. Expected: the same.
4. Run `docker compose -f dev/docker-compose.yml up -d postgres && DATABASE_ADAPTER=postgres pnpm dev` and repeat. Expected: the same.
5. Stop the server.

**Step 9: Commit.**

```bash
git add dev
git commit -m "chore: add the dev app with MongoDB, SQLite and Postgres configs"
```

### Task 3: Test harness: Vitest projects, database setup and an in-process REST client

**Files:**
- Create: `vitest.config.ts`, `test/globalSetup.ts`, `test/configs/single.ts`, `test/configs/multi.ts`, `test/helpers/api.ts`, `test/helpers/users.ts`
- Test: `test/int/smoke.int.spec.ts`

**Step 1: Write the failing smoke test.** Create `test/int/smoke.int.spec.ts`:

```ts
import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import config from '../configs/single.js'
import { createClient } from '../helpers/api.js'
import { createUser, PASSWORD } from '../helpers/users.js'

let payload: Payload

beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

describe('harness', () => {
  it('answers /me anonymously', async () => {
    const me = await createClient(config).get('/api/users/me')
    expect(me.status).toBe(200)
    expect(me.json.user).toBeNull()
  })

  it('keeps the session cookie across calls', async () => {
    const user = await createUser(payload, 'users')
    const client = createClient(config)
    const login = await client.post('/api/users/login', { email: user.email, password: PASSWORD })
    expect(login.status).toBe(200)
    const me = await client.get('/api/users/me')
    expect(me.json.user.id).toBe(user.id)
  })
})
```

Run `pnpm test:int test/int/smoke.int.spec.ts`. Expected: FAIL, "Cannot find module '../configs/single.js'".

**Step 2: Write `vitest.config.ts`.**

```ts
import path from 'path'
import { loadEnv } from 'payload/node'
import { fileURLToPath } from 'url'
import tsconfigPaths from 'vite-tsconfig-paths'
import { defineConfig } from 'vitest/config'

const dirname = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig(() => {
  loadEnv(path.resolve(dirname, './dev'))

  return {
    plugins: [tsconfigPaths({ ignoreConfigErrors: true, projects: ['./dev/tsconfig.json'] })],
    test: {
      projects: [
        {
          extends: true,
          test: { environment: 'node', include: ['test/unit/**/*.spec.ts'], name: 'unit' },
        },
        {
          extends: true,
          test: {
            env: {
              NODE_ENV: 'test',
              PAYLOAD_DROP_DATABASE: 'true',
              PAYLOAD_SECRET: 'integration-test-secret-not-for-production',
            },
            environment: 'node',
            fileParallelism: false,
            globalSetup: ['test/globalSetup.ts'],
            hookTimeout: 120_000,
            include: ['test/int/**/*.int.spec.ts'],
            name: 'int',
            pool: 'forks',
            testTimeout: 60_000,
          },
        },
      ],
    },
  }
})
```

**Step 3: Write `test/globalSetup.ts`.** Forked workers inherit `process.env` from this process.

```ts
import { mkdirSync, rmSync } from 'fs'
import { MongoMemoryReplSet } from 'mongodb-memory-server'
import path from 'path'

export default async function setup(): Promise<() => Promise<void>> {
  const adapter = process.env.DATABASE_ADAPTER ?? 'mongo'

  if (adapter === 'mongo' && !process.env.DATABASE_URL) {
    const replSet = await MongoMemoryReplSet.create({
      replSet: { count: 1, storageEngine: 'wiredTiger' },
    })
    process.env.DATABASE_URL = replSet.getUri('payload-passkeys-test')
    return async () => {
      await replSet.stop()
    }
  }

  if (adapter === 'sqlite' && !process.env.DATABASE_URL) {
    const dir = path.resolve('test/.tmp')
    mkdirSync(dir, { recursive: true })
    const file = path.join(dir, `int-${process.pid}.db`)
    process.env.DATABASE_URL = `file:${file}`
    return async () => {
      rmSync(file, { force: true })
    }
  }

  if (adapter === 'postgres' && !process.env.DATABASE_URL) {
    process.env.DATABASE_URL = 'postgres://postgres:postgres@127.0.0.1:5432/payload_passkeys'
  }
  return async () => {}
}
```

**Step 4: Write `test/configs/single.ts` and `test/configs/multi.ts`.**

```ts
// test/configs/single.ts
import { buildDevConfig } from '../../dev/buildConfig.js'

export default buildDevConfig({
  plugin: { limits: { anonymousChallenges: 50, passkeysPerUser: 3 } },
  variant: 'single',
})
```

`test/configs/multi.ts` is the same with `variant: 'multi'`. Until Task 11, the `plugin` argument is a no-op; leave `limits` commented out.

**Step 5: Write `test/helpers/api.ts`, complete.**

```ts
import type { SanitizedConfig } from 'payload'

import { handleEndpoints } from 'payload'

export const SERVER_URL = 'http://localhost:3000'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ApiResult<T = any> = { headers: Headers; json: T; status: number }

type RequestOptions = {
  body?: unknown
  /** Send the body raw with this content type instead of as JSON. */
  contentType?: string
  headers?: Record<string, string>
}

export type TestClient = {
  cookies: Map<string, string>
  delete: (path: string, options?: RequestOptions) => Promise<ApiResult>
  get: (path: string, options?: RequestOptions) => Promise<ApiResult>
  patch: (path: string, body?: unknown, options?: RequestOptions) => Promise<ApiResult>
  post: (path: string, body?: unknown, options?: RequestOptions) => Promise<ApiResult>
  request: (method: string, path: string, options?: RequestOptions) => Promise<ApiResult>
  /** Put a Set-Cookie line (as returned by mintSession) into the jar. */
  setCookie: (line: string) => void
}

const applySetCookie = (jar: Map<string, string>, line: string): void => {
  const [pair = '', ...attributes] = line.split(';')
  const index = pair.indexOf('=')
  if (index < 1) return
  const name = pair.slice(0, index).trim()
  const value = pair.slice(index + 1).trim()
  const expired = attributes.some((attribute) => {
    const [key = '', raw = ''] = attribute.trim().split('=')
    if (key.toLowerCase() === 'max-age') return Number(raw) <= 0
    if (key.toLowerCase() === 'expires') return Date.parse(raw) <= Date.now()
    return false
  })
  if (expired || value === '') jar.delete(name)
  else jar.set(name, value)
}

/**
 * Drives Payload's whole REST stack in-process (auth strategies, CSRF, plugin and core endpoints)
 * with a cookie jar. `origin: null` sends no Origin header.
 */
export const createClient = (
  config: Promise<SanitizedConfig> | SanitizedConfig,
  { origin = SERVER_URL }: { origin?: null | string } = {},
): TestClient => {
  const cookies = new Map<string, string>()

  const request = async (method: string, path: string, options: RequestOptions = {}) => {
    const headers = new Headers(options.headers)
    if (origin && !headers.has('Origin')) headers.set('Origin', origin)
    let body: string | undefined
    if (options.body !== undefined) {
      body = typeof options.body === 'string' ? options.body : JSON.stringify(options.body)
      if (!headers.has('Content-Type')) headers.set('Content-Type', options.contentType ?? 'application/json')
    }
    if (cookies.size) {
      headers.set('Cookie', [...cookies].map(([name, value]) => `${name}=${value}`).join('; '))
    }
    const response = await handleEndpoints({
      config,
      request: new Request(`${SERVER_URL}${path}`, { body, headers, method }),
    })
    for (const line of response.headers.getSetCookie()) applySetCookie(cookies, line)
    const text = await response.text()
    let json: unknown = null
    try {
      json = text ? JSON.parse(text) : null
    } catch {
      json = text
    }
    return { headers: response.headers, json, status: response.status } as ApiResult
  }

  return {
    cookies,
    delete: (path, options) => request('DELETE', path, options),
    get: (path, options) => request('GET', path, options),
    patch: (path, body, options) => request('PATCH', path, { ...options, body }),
    post: (path, body, options) => request('POST', path, { ...options, body: body ?? {} }),
    request,
    setCookie: (line) => applySetCookie(cookies, line),
  }
}

/** A new client that carries only the given cookies (to replay an old token after logout). */
export const cloneWithCookies = (
  config: Promise<SanitizedConfig> | SanitizedConfig,
  cookies: Map<string, string>,
): TestClient => {
  const client = createClient(config)
  for (const [name, value] of cookies) client.cookies.set(name, value)
  return client
}
```

**Step 6: Write `test/helpers/users.ts`.**

```ts
import type { Payload } from 'payload'

import { randomUUID } from 'crypto'

export const PASSWORD = 'correct horse battery staple'

export type TestUser = { collection: string; email: string; id: number | string }

export const createUser = async (
  payload: Payload,
  collection: 'customers' | 'users',
  data: Record<string, unknown> = {},
): Promise<TestUser> => {
  const email = `${collection}-${randomUUID()}@example.test`
  const doc = (await payload.create({
    collection,
    data: { email, password: PASSWORD, ...(collection === 'users' ? { name: 'Test User' } : {}), ...data },
    disableVerificationEmail: true,
  } as never)) as { id: number | string }
  if (collection === 'customers') {
    await payload.db.updateOne({ collection, data: { _verified: true }, id: doc.id, returning: false })
  }
  return { collection, email, id: doc.id }
}

export const rawUser = async (payload: Payload, collection: string, id: number | string) =>
  (await payload.db.findOne({ collection, where: { id: { equals: id } } })) as Record<string, unknown> & {
    loginAttempts?: number
    lockUntil?: null | string
    sessions?: { createdAt?: string; expiresAt: string; id: string }[]
  }
```

**Step 7: Run the smoke test.**

Run `pnpm test:int test/int/smoke.int.spec.ts`. Expected: PASS (2 tests). Then run `DATABASE_ADAPTER=sqlite pnpm test:int test/int/smoke.int.spec.ts` and the Postgres equivalent. Expected: PASS on each.

**Step 8: Commit.**

```bash
git add vitest.config.ts test
git commit -m "test: add an in-process REST client and integration harness for three adapters"
```

### Task 4: Client-import boundary and client dependency graph tests

These come before any component code exists, so a server import can never reach `./client` or `./rsc` unnoticed (design §6 "Client bundle", review L9).

**Files:**
- Create: `test/helpers/importGraph.ts`
- Test: `test/unit/clientBoundary.spec.ts`

**Step 1: Write the failing test, complete.**

```ts
// test/unit/clientBoundary.spec.ts
import path from 'path'
import { describe, expect, it } from 'vitest'

import { scanImports, walkClientGraph } from '../helpers/importGraph.js'

const root = path.resolve(import.meta.dirname, '../..')

/** Every bare import a client or RSC entry may make at runtime (type imports are free). */
const ALLOWED_BARE = new Set([
  '@payloadcms/ui',
  '@simplewebauthn/browser',
  'next/navigation.js',
  'payload/shared',
  'react',
  'react/jsx-runtime',
])

describe('scanImports', () => {
  it('finds value imports and skips type-only ones', () => {
    const found = scanImports(
      [
        `import type { A } from 'payload'`,
        `export type { B } from './b.js'`,
        `import { type C, d } from './d.js'`,
        `import React, {\n  useState,\n} from 'react'`,
        `import './side-effect.css'`,
        `export { e } from '../server/e.js'`,
        `const lazy = await import('@simplewebauthn/server')`,
      ].join('\n'),
    )
    expect(found.filter((f) => !f.typeOnly).map((f) => f.specifier)).toEqual([
      './d.js',
      'react',
      './side-effect.css',
      '../server/e.js',
      '@simplewebauthn/server',
    ])
    expect(found.filter((f) => f.typeOnly).map((f) => f.specifier)).toEqual(['payload', './b.js'])
  })
})

describe.each(['src/exports/client.ts', 'src/exports/rsc.ts'])('%s', (entry) => {
  const graph = walkClientGraph(path.join(root, entry))

  it('reaches no server module', () => {
    const forbidden = graph.files.filter((file) =>
      /[/\\]src[/\\](server|collections|bin|translations)[/\\]|[/\\]src[/\\]index\.ts$/.test(file),
    )
    expect(forbidden).toEqual([])
  })

  it('imports only the allowed packages at runtime', () => {
    const disallowed = [...graph.bare].filter((specifier) => !ALLOWED_BARE.has(specifier))
    expect(disallowed).toEqual([])
  })
})
```

Run `pnpm test:unit test/unit/clientBoundary.spec.ts`. Expected: FAIL, "Cannot find module '../helpers/importGraph.js'".

**Step 2: Write `test/helpers/importGraph.ts`, complete.**

```ts
import { existsSync, readFileSync, statSync } from 'fs'
import path from 'path'

export type FoundImport = { specifier: string; typeOnly: boolean }

const STATIC = /(?:^|[\s;])(import|export)\s+(type\s+)?(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]/g
const DYNAMIC = /import\(\s*['"]([^'"]+)['"]\s*\)/g

/** Lists the module specifiers in a source file, in order, marking `import type` / `export type`. */
export const scanImports = (source: string): FoundImport[] => {
  const found: { index: number; value: FoundImport }[] = []
  for (const match of source.matchAll(STATIC)) {
    const [, , typeKeyword, specifier] = match
    if (specifier) found.push({ index: match.index, value: { specifier, typeOnly: Boolean(typeKeyword) } })
  }
  for (const match of source.matchAll(DYNAMIC)) {
    if (match[1]) found.push({ index: match.index, value: { specifier: match[1], typeOnly: false } })
  }
  return found.sort((a, b) => a.index - b.index).map((entry) => entry.value)
}

const resolveRelative = (from: string, specifier: string): null | string => {
  const base = path.resolve(path.dirname(from), specifier)
  const candidates = [
    base.replace(/\.js$/, '.ts'),
    base.replace(/\.js$/, '.tsx'),
    base,
    path.join(base, 'index.ts'),
    path.join(base, 'index.tsx'),
  ]
  return candidates.find((candidate) => existsSync(candidate) && statSync(candidate).isFile()) ?? null
}

/** Walks the runtime import graph from an entry file. */
export const walkClientGraph = (entry: string): { bare: Set<string>; files: string[] } => {
  const seen = new Set<string>()
  const bare = new Set<string>()
  const queue = [entry]
  while (queue.length) {
    const file = queue.shift()!
    if (seen.has(file)) continue
    seen.add(file)
    for (const { specifier, typeOnly } of scanImports(readFileSync(file, 'utf8'))) {
      if (typeOnly) continue
      if (specifier.startsWith('.')) {
        if (/\.(css|scss|svg|json)$/.test(specifier)) continue
        const resolved = resolveRelative(file, specifier)
        if (!resolved) throw new Error(`Cannot resolve ${specifier} from ${file}`)
        queue.push(resolved)
      } else {
        bare.add(specifier)
      }
    }
  }
  return { bare, files: [...seen] }
}
```

**Step 3: Run the test.**

Run `pnpm test:unit test/unit/clientBoundary.spec.ts`. Expected: PASS (5 tests; the entries are still empty).

**Step 4: Commit.**

```bash
git add test/helpers/importGraph.ts test/unit/clientBoundary.spec.ts
git commit -m "test: enforce the client import boundary and the client dependency allowlist"
```

## Milestone M1: session spike (the riskiest unknown)

End state: `mintSession` is proved against a real Payload boot on all three adapters. Its cookie authenticates `/me`; refresh extends it; logout, logout-all and a password change from another session revoke it. Hooks, lockout and secrets behave as specified. **Do not start M2 until Task 9 is green on MongoDB, SQLite and Postgres.**

### Task 5: Public types and shared constants

**Files:**
- Create: `src/types.ts`, `src/shared/constants.ts`
- Test: none (types only; later tests use them)

**Step 1: Write `src/types.ts`.**

```ts
import type { PayloadRequest } from 'payload'

export type PasskeyAction =
  | 'delete'
  | 'reauth'
  | 'register.options'
  | 'register.verify'
  | 'rename'
  | 'sign-in.options'
  | 'sign-in.verify'
  | 'status'

export type RateLimitArgs = {
  action: PasskeyAction
  collection: string
  /**
   * From `x-real-ip`, else the first `x-forwarded-for` entry. Trustworthy only behind a proxy that
   * sets these headers itself (Vercel does); otherwise a client can choose its own value.
   */
  ip: null | string
  /** `<collection>:<userId>` for signed-in calls, `ip:<ip>` for anonymous ones. */
  key: string
  req: PayloadRequest
  userId?: number | string
}

/** Return true to allow the request. A throw or anything but true refuses it with 429. */
export type RateLimitHook = (args: RateLimitArgs) => boolean | Promise<boolean>

export type DeviceType = 'multiDevice' | 'singleDevice'

/** What the plugin ever sends to a browser about a passkey. No public key, no counter. */
export type PublicPasskey = {
  aaguid: null | string
  backedUp: boolean
  createdAt: string
  credentialId: string
  deviceType: DeviceType
  id: number | string
  lastUsedAt: null | string
  name: string
  rpID: string
  transports: string[]
}

export type OnSignInArgs = {
  collection: string
  passkey?: PublicPasskey
  req: PayloadRequest
  user: Record<string, unknown>
}

/**
 * Runs inside the sign-in transaction after the collection's beforeLogin hooks and before the token
 * is signed. Throw to refuse the sign-in; the new session is revoked. Exists because passkey
 * sign-in does not run the collection's beforeOperation/afterOperation hooks (review L8).
 */
export type OnSignInHook = (args: OnSignInArgs) => Promise<void> | void

export type PasskeysPluginOptions = {
  /** Auth collections that get passkeys. Default: [admin.user] (or the first auth collection). */
  collections?: string[]
  /** false keeps the schema (fields and collections) but adds no endpoints or admin components. */
  enabled?: boolean
  /** Offer "Sign in faster with a passkey" after a password sign-in. Default true. */
  enrolmentPrompt?: boolean
  /** How recent a sign-in must be to add a passkey without re-entering the password. Default 10. */
  freshSessionMinutes?: number
  limits?: {
    /** Outstanding anonymous sign-in challenges across the site, then 429. Default 500. */
    anonymousChallenges?: number
    /** Passkeys per user. Default 20. */
    passkeysPerUser?: number
  }
  /** IP addresses in failure logs. Default 'truncated' (/24, /48). Never logged on success. */
  logging?: { ip?: 'full' | 'none' | 'truncated' }
  onSignIn?: OnSignInHook
  /** Exact origins (scheme, host, port) the admin is served from. Default: [serverURL origin]. */
  origins?: string[]
  rateLimit?: RateLimitHook
  /** WebAuthn relying-party ID. Default: hostname of serverURL. */
  rpID?: string
  /** Shown by some passkey managers. Default: admin.meta.title, else the RP ID. */
  rpName?: string
  slugs?: { challengeUses?: string; challenges?: string; passkeys?: string }
}
```

**Step 2: Write `src/shared/constants.ts`.**

```ts
export const PACKAGE_NAME = '@the-digital-stride/payload-passkeys'

export const DEFAULT_SLUGS = {
  challengeUses: 'passkey-challenge-uses',
  challenges: 'passkey-challenges',
  passkeys: 'passkeys',
} as const

export const USER_HANDLE_FIELD = 'passkeyUserHandle'
export const MANAGER_FIELD = 'passkeysManager'

export const CHALLENGE_TTL_MS = 5 * 60 * 1000
export const CEREMONY_TIMEOUT_MS = 5 * 60 * 1000
export const MAX_PASSKEY_NAME = 64
/** EdDSA, ES256, RS256 (WebAuthn L3 §5.4). */
export const SUPPORTED_ALGORITHM_IDS = [-8, -7, -257]

export const ENDPOINTS = {
  delete: '/passkeys/delete',
  reauth: '/passkeys/reauth',
  registerOptions: '/passkeys/register/options',
  registerVerify: '/passkeys/register/verify',
  rename: '/passkeys/rename',
  signInOptions: '/passkeys/sign-in/options',
  signInVerify: '/passkeys/sign-in/verify',
  status: '/passkeys/status',
} as const

/** Error codes the endpoints return as { error }. The client maps each to copy. */
export type PasskeysErrorCode =
  | 'bad_request'
  | 'busy'
  | 'forbidden_origin'
  | 'not_found'
  | 'rate_limited'
  | 'reauth_failed'
  | 'reauth_required'
  | 'registration_failed'
  | 'sign_in_failed'
  | 'too_many_passkeys'
  | 'unauthorised'
```

**Step 3: Type-check and commit.**

Run `pnpm typecheck`. Expected: no errors.

```bash
git add src/types.ts src/shared/constants.ts
git commit -m "feat: add public option types and shared constants"
```

### Task 6: Contract tests for `mintSession` (write them first)

**Files:**
- Create: `test/helpers/secrets.ts`, `test/helpers/requests.ts`
- Test: `test/int/mintSession.contract.int.spec.ts`

**Step 1: Write the helpers.**

```ts
// test/helpers/secrets.ts
export const SECRET_KEYS = [
  'hash',
  'salt',
  'sessions',
  'apiKey',
  'apiKeyIndex',
  'resetPasswordToken',
  'resetPasswordExpiration',
  '_verificationToken',
  'passkeyUserHandle',
  'publicKey',
  'counter',
] as const

/** Every secret key found anywhere in a JSON value, with its path. */
export const findSecretKeys = (value: unknown, path = '$'): string[] => {
  if (Array.isArray(value)) return value.flatMap((item, i) => findSecretKeys(item, `${path}[${i}]`))
  if (!value || typeof value !== 'object') return []
  return Object.entries(value).flatMap(([key, child]) => [
    ...((SECRET_KEYS as readonly string[]).includes(key) ? [`${path}.${key}`] : []),
    ...findSecretKeys(child, `${path}.${key}`),
  ])
}
```

```ts
// test/helpers/requests.ts
import type { PayloadRequest, SanitizedConfig } from 'payload'

import { createPayloadRequest } from 'payload'

import type { TestClient } from './api.js'

import { SERVER_URL } from './api.js'

/** A PayloadRequest authenticated by the client's cookies, as an endpoint would see it. */
export const requestFor = async (
  config: Promise<SanitizedConfig>,
  path: string,
  client?: TestClient,
): Promise<PayloadRequest> => {
  const headers = new Headers({ 'Content-Type': 'application/json', Origin: SERVER_URL })
  if (client?.cookies.size) {
    headers.set('Cookie', [...client.cookies].map(([n, v]) => `${n}=${v}`).join('; '))
  }
  return createPayloadRequest({
    config,
    request: new Request(`${SERVER_URL}${path}`, { headers, method: 'POST' }),
  })
}

export const missingUserId = (): number | string =>
  (process.env.DATABASE_ADAPTER ?? 'mongo') === 'mongo' ? '000000000000000000000000' : 999_999_999
```

**Step 2: Write the contract spec, complete.**

```ts
// test/int/mintSession.contract.int.spec.ts
import type { Payload } from 'payload'

import { getPayload, JWT_AUTH_VERSION } from 'payload'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { testHooks } from '../../dev/testHooks.js'
import { mintSession, SignInRefused } from '../../src/server/mintSession.js'
import config from '../configs/multi.js'
import { cloneWithCookies, createClient } from '../helpers/api.js'
import { missingUserId, requestFor } from '../helpers/requests.js'
import { findSecretKeys } from '../helpers/secrets.js'
import { createUser, PASSWORD, rawUser } from '../helpers/users.js'

let payload: Payload

beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})
beforeEach(() => {
  testHooks.reset()
})

const mint = async (collection: 'customers' | 'users', userId: number | string) =>
  mintSession({
    collectionSlug: collection,
    req: await requestFor(config, `/api/${collection}/passkeys/sign-in/verify`),
    userId,
  })

const clientFrom = (setCookie: string) => {
  const client = createClient(config)
  client.setCookie(setCookie)
  return client
}

const passwordClient = async (email: string, collection = 'users') => {
  const client = createClient(config)
  const res = await client.post(`/api/${collection}/login`, { email, password: PASSWORD })
  expect(res.status).toBe(200)
  return client
}

const decodeSegment = (token: string, index: 0 | 1) =>
  JSON.parse(Buffer.from(token.split('.')[index]!, 'base64url').toString('utf8'))

describe('mintSession: the minted session is a native Payload session', () => {
  it('authenticates /me', async () => {
    const user = await createUser(payload, 'users')
    const minted = await mint('users', user.id)
    const me = await clientFrom(minted.setCookie).get('/api/users/me')
    expect(me.status).toBe(200)
    expect(me.json.user.id).toBe(user.id)
    expect(me.json.collection).toBe('users')
    expect(me.json.strategy).toBe('local-jwt')
  })

  it('signs with the current authVersion and carries sid, id and collection', async () => {
    const user = await createUser(payload, 'users')
    const minted = await mint('users', user.id)
    const token = clientFrom(minted.setCookie).cookies.get('payload-token')!
    expect(decodeSegment(token, 0).authVersion).toBe(JWT_AUTH_VERSION)
    const claims = decodeSegment(token, 1)
    expect(claims).toMatchObject({ collection: 'users', email: user.email, id: user.id, sid: minted.sid })
    expect(minted.body.exp).toBe(claims.exp)
  })

  it('is extended by /refresh-token', async () => {
    const user = await createUser(payload, 'users')
    const minted = await mint('users', user.id)
    const soon = new Date(Date.now() + 60_000).toISOString()
    const { sessions = [] } = await rawUser(payload, 'users', user.id)
    await payload.db.updateOne({
      collection: 'users',
      data: { sessions: sessions.map((s) => (s.id === minted.sid ? { ...s, expiresAt: soon } : s)) },
      id: user.id,
      returning: false,
    })
    const refreshed = await clientFrom(minted.setCookie).post('/api/users/refresh-token')
    expect(refreshed.status).toBe(200)
    expect(typeof refreshed.json.refreshedToken).toBe('string')
    const after = (await rawUser(payload, 'users', user.id)).sessions!.find((s) => s.id === minted.sid)!
    expect(Date.parse(after.expiresAt)).toBeGreaterThan(Date.now() + 3_600_000)
  })

  it('is revoked by logout', async () => {
    const user = await createUser(payload, 'users')
    const client = clientFrom((await mint('users', user.id)).setCookie)
    const saved = new Map(client.cookies)
    expect((await client.post('/api/users/logout')).status).toBe(200)
    expect((await cloneWithCookies(config, saved).get('/api/users/me')).json.user).toBeNull()
  })

  it('is revoked by "log out of all sessions" from another session', async () => {
    const user = await createUser(payload, 'users')
    const minted = clientFrom((await mint('users', user.id)).setCookie)
    const other = await passwordClient(user.email)
    expect((await other.post('/api/users/logout?allSessions=true')).status).toBe(200)
    expect((await minted.get('/api/users/me')).json.user).toBeNull()
  })

  it('is revoked by a password change made from another session', async () => {
    const user = await createUser(payload, 'users')
    const minted = clientFrom((await mint('users', user.id)).setCookie)
    const other = await passwordClient(user.email)
    const changed = await other.patch(`/api/users/${user.id}`, { password: 'a different long passphrase' })
    expect(changed.status).toBe(200)
    expect((await minted.get('/api/users/me')).json.user).toBeNull()
    expect((await other.get('/api/users/me')).json.user.id).toBe(user.id)
  })

  it('survives a password change made from itself (core keeps the current session)', async () => {
    const user = await createUser(payload, 'users')
    const minted = clientFrom((await mint('users', user.id)).setCookie)
    expect((await minted.patch(`/api/users/${user.id}`, { password: 'another long passphrase' })).status).toBe(200)
    expect((await minted.get('/api/users/me')).json.user.id).toBe(user.id)
  })
})

describe('mintSession: account rules', () => {
  it('refuses a user that does not exist', async () => {
    await expect(mint('users', missingUserId())).rejects.toMatchObject({ reason: 'user_missing' })
  })

  it('refuses an unverified user', async () => {
    const user = await createUser(payload, 'customers')
    await payload.db.updateOne({ collection: 'customers', data: { _verified: false }, id: user.id, returning: false })
    const error = await mint('customers', user.id).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(SignInRefused)
    expect((error as SignInRefused).reason).toBe('unverified')
    expect((await rawUser(payload, 'customers', user.id)).sessions ?? []).toHaveLength(0)
  })

  it('does not refuse a locked user, reports it, and resets the attempts (review M5)', async () => {
    const user = await createUser(payload, 'users')
    const lockUntil = new Date(Date.now() + 600_000).toISOString()
    await payload.db.updateOne({ collection: 'users', data: { lockUntil, loginAttempts: 5 }, id: user.id, returning: false })
    const minted = await mint('users', user.id)
    expect(minted.wasLocked).toBe(true)
    const raw = await rawUser(payload, 'users', user.id)
    expect(raw.loginAttempts).toBe(0)
    expect(raw.lockUntil ?? null).toBeNull()
    expect((await clientFrom(minted.setCookie).get('/api/users/me')).json.user.id).toBe(user.id)
  })

  it('revokes the new session when a beforeLogin hook throws', async () => {
    const user = await createUser(payload, 'users')
    testHooks.beforeLogin = () => {
      throw new Error('blocked by host rule')
    }
    await expect(mint('users', user.id)).rejects.toThrow('blocked by host rule')
    expect((await rawUser(payload, 'users', user.id)).sessions ?? []).toHaveLength(0)
  })

  it('revokes the new session when onSignIn throws', async () => {
    const user = await createUser(payload, 'users')
    const req = await requestFor(config, '/api/users/passkeys/sign-in/verify')
    await expect(
      mintSession({
        collectionSlug: 'users',
        onSignIn: () => {
          throw new Error('geo rule')
        },
        req,
        userId: user.id,
      }),
    ).rejects.toThrow('geo rule')
    expect((await rawUser(payload, 'users', user.id)).sessions ?? []).toHaveLength(0)
  })

  it('passes beforeLogin the user and afterLogin the token', async () => {
    const user = await createUser(payload, 'users')
    const seen: Record<string, unknown>[] = []
    testHooks.beforeLogin = (args) => void seen.push({ hook: 'before', ...args })
    testHooks.afterLogin = (args) => void seen.push({ hook: 'after', ...args })
    await mint('users', user.id)
    expect(seen.map((s) => s.hook)).toEqual(['before', 'after'])
    expect((seen[0]!.user as { id: unknown }).id).toBe(user.id)
    expect(typeof seen[1]!.token).toBe('string')
  })
})

describe('mintSession: response body', () => {
  it('has the shape useAuth().setUser expects', async () => {
    const user = await createUser(payload, 'users')
    const { body } = await mint('users', user.id)
    expect(typeof body.exp).toBe('number')
    expect(typeof body.token).toBe('string')
    expect(body.user).toMatchObject({ collection: 'users', email: user.email, id: user.id })
  })

  it('omits the token when removeTokenFromResponses is on', async () => {
    const user = await createUser(payload, 'customers')
    const { body } = await mint('customers', user.id)
    expect(body.token).toBeUndefined()
  })

  it('never contains hash, salt, sessions, apiKey or other secrets (review M1)', async () => {
    const user = await createUser(payload, 'users', { apiKey: crypto.randomUUID(), enableAPIKey: true })
    const { body } = await mint('users', user.id)
    expect(findSecretKeys(body)).toEqual([])
  })
})
```

**Step 3: Run it and watch it fail.**

Run `pnpm test:int test/int/mintSession.contract.int.spec.ts`. Expected: FAIL, "Cannot find module '../../src/server/mintSession.js'".

**Step 4: Commit the failing tests.**

```bash
git add test/helpers/secrets.ts test/helpers/requests.ts test/int/mintSession.contract.int.spec.ts
git commit -m "test: add the mintSession contract tests"
```

### Task 7: Implement `mintSession`

> **Implemented as (2026-11-06):** as below, with `onSignIn` after the `beforeLogin` hooks and before `jwtSign` and the `afterLogin` hooks. `reauthenticate` (in this module, pinned by Task 8) gained the wrong-account check, builds its response before revoking the old session, and logs a failed revoke instead of throwing (Verified facts Q1).

**Files:**
- Create: `src/server/mintSession.ts`
- Test: `test/int/mintSession.contract.int.spec.ts` (from Task 6)

**Step 1: Write `src/server/mintSession.ts`, complete.** This is the only module that imports Payload's undocumented auth helpers. Keep it that way: a Payload minor that changes them should break this file and its contract test, nothing else.

```ts
/**
 * The Payload adapter. Every undocumented Payload auth helper the plugin uses is imported here and
 * nowhere else, and test/int/mintSession.contract.int.spec.ts pins its behaviour per Payload minor.
 *
 * Differences from loginOperation, by design:
 * - no password check (the caller verified a passkey);
 * - lockUntil does not refuse a passkey sign-in (review M5); the caller logs it;
 * - beforeOperation/afterOperation for 'login' are not run (not exported; review L8). The plugin's
 *   onSignIn option is the documented substitute.
 */
import type { CollectionSlug, PayloadRequest, SanitizedCollectionConfig, TypedUser } from 'payload'

import {
  commitTransaction,
  getFieldsToSign,
  initTransaction,
  jwtSign,
  killTransaction,
  loginOperation,
  resetLoginAttempts,
} from 'payload'
import { addSessionToUser, generatePayloadCookie, getLoginOptions } from 'payload/shared'

import type { OnSignInHook, PublicPasskey } from '../types.js'

import { USER_HANDLE_FIELD } from '../shared/constants.js'

type Session = { createdAt?: Date | null | string; expiresAt: Date | string; id: string }

export type RawUser = Record<string, unknown> & {
  email?: string
  id: number | string
  lockUntil?: Date | null | string
  sessions?: Session[]
  username?: string
}

export type SignInResponseBody = {
  exp: number
  message: string
  token?: string
  user: Record<string, unknown>
}

export type SessionResult = { body: SignInResponseBody; setCookie: string; sid: string }
export type MintResult = SessionResult & { wasLocked: boolean }

export class SignInRefused extends Error {
  readonly reason: string
  constructor(reason: string) {
    super(`Passkey sign-in refused: ${reason}`)
    this.name = 'SignInRefused'
    this.reason = reason
  }
}

/** Never sent to a browser, even where field access would let the owner read them (review M1). */
export const SECRET_USER_KEYS = [
  'hash',
  'salt',
  'sessions',
  'apiKey',
  'apiKeyIndex',
  'resetPasswordToken',
  'resetPasswordExpiration',
  '_verificationToken',
  'loginAttempts',
  'lockUntil',
  USER_HANDLE_FIELD,
] as const

export const authCollectionConfig = (req: PayloadRequest, slug: string): SanitizedCollectionConfig => {
  const collection = req.payload.collections[slug as CollectionSlug]
  if (!collection?.config.auth) throw new SignInRefused('not_an_auth_collection')
  return collection.config
}

export const isLocked = (lockUntil: unknown): boolean => {
  if (!lockUntil) return false
  const until = new Date(lockUntil as string).getTime()
  return Number.isFinite(until) && until > Date.now()
}

/** The raw stored user (hash, salt and sessions included). Never return it to a client. */
export const loadRawUser = async (
  req: PayloadRequest,
  slug: string,
  id: number | string,
): Promise<null | RawUser> => {
  const config = authCollectionConfig(req, slug)
  const byId = { id: { equals: id } }
  const where = config.trash ? { and: [byId, { deletedAt: { exists: false } }] } : byId
  return (await req.payload.db.findOne({ collection: slug, req, where })) as null | RawUser
}

/** The identifier Payload's login operation expects for this user. */
export const loginIdentifier = (
  config: SanitizedCollectionConfig,
  user: RawUser,
): { email: string } | { username: string } => {
  const { canLoginWithEmail } = getLoginOptions(config.auth.loginWithUsername)
  if (canLoginWithEmail && typeof user.email === 'string' && user.email) return { email: user.email }
  if (typeof user.username === 'string' && user.username) return { username: user.username }
  throw new SignInRefused('no_login_identifier')
}

/** The user as /me would show it to its owner, minus every secret (review M1). */
export const toResponseUser = async ({
  collectionSlug,
  req,
  sid,
  user,
}: {
  collectionSlug: string
  req: PayloadRequest
  sid: string
  user: RawUser
}): Promise<Record<string, unknown>> => {
  const config = authCollectionConfig(req, collectionSlug)
  const doc = (await req.payload.findByID({
    collection: collectionSlug as CollectionSlug,
    depth: config.auth.depth,
    id: user.id,
    overrideAccess: false,
    req,
    showHiddenFields: false,
    user: { ...user, _sid: sid, _strategy: 'local-jwt', collection: collectionSlug } as unknown as TypedUser,
  })) as Record<string, unknown>
  const clean: Record<string, unknown> = { ...doc }
  for (const key of SECRET_USER_KEYS) delete clean[key]
  return { ...clean, _strategy: 'local-jwt', collection: collectionSlug }
}

/**
 * Removes sessions from a user, with the same whole-document write core's logout uses.
 * `only`: remove these sids. Otherwise keep only `keep` (or none). Returns how many were removed.
 */
export const revokeSessions = async ({
  collectionSlug,
  keep,
  only,
  req,
  userId,
}: {
  collectionSlug: string
  keep?: string
  only?: string[]
  req: PayloadRequest
  userId: number | string
}): Promise<number> => {
  const user = await loadRawUser(req, collectionSlug, userId)
  if (!user || !Array.isArray(user.sessions) || user.sessions.length === 0) return 0
  const before = user.sessions.length
  user.sessions = user.sessions.filter((session) =>
    only ? !only.includes(session.id) : session.id === keep,
  )
  if (user.sessions.length === before) return 0
  user.updatedAt = null
  await req.payload.db.updateOne({ collection: collectionSlug, data: user, id: userId, req, returning: false })
  return before - user.sessions.length
}

const sidFromToken = (token: string): string => {
  const claims = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8')) as {
    sid?: unknown
  }
  if (typeof claims.sid !== 'string') throw new SignInRefused('no_session_id')
  return claims.sid
}

const cookieFor = (req: PayloadRequest, config: SanitizedCollectionConfig, token: string): string =>
  generatePayloadCookie({
    collectionAuthConfig: config.auth,
    cookiePrefix: req.payload.config.cookiePrefix,
    token,
  })

/**
 * Mints an ordinary Payload session for a user who has just proved a passkey. Mirrors
 * loginOperation's order (Payload 3.90.2): transaction, addSessionToUser, getFieldsToSign,
 * resetLoginAttempts, beforeLogin, jwtSign, afterLogin, commit; on any throw, revoke and roll back.
 */
export const mintSession = async ({
  collectionSlug,
  onSignIn,
  passkey,
  req,
  userId,
}: {
  collectionSlug: string
  onSignIn?: OnSignInHook
  passkey?: PublicPasskey
  req: PayloadRequest
  userId: number | string
}): Promise<MintResult> => {
  const { payload } = req
  const config = authCollectionConfig(req, collectionSlug)
  const auth = config.auth
  if (!auth.useSessions) throw new SignInRefused('sessions_disabled')

  const user = await loadRawUser(req, collectionSlug, userId)
  if (!user) throw new SignInRefused('user_missing')
  if (auth.verify && user._verified === false) throw new SignInRefused('unverified')
  const wasLocked = isLocked(user.lockUntil)

  user.collection = collectionSlug
  user._strategy = 'local-jwt'

  const shouldCommit = await initTransaction(req)
  let sid: string | undefined
  try {
    sid = (await addSessionToUser({ collectionConfig: config, payload, req, user: user as unknown as TypedUser })).sid
    if (!sid) throw new SignInRefused('sessions_disabled')
    user._sid = sid

    const fieldsToSign = getFieldsToSign({
      collectionConfig: config,
      email: typeof user.email === 'string' ? user.email : '',
      sid,
      user: user as unknown as PayloadRequest['user'],
    })

    if (auth.maxLoginAttempts > 0) {
      await resetLoginAttempts({ collection: config, doc: user, payload, req })
    }

    let hookedUser: RawUser = user
    for (const hook of config.hooks?.beforeLogin ?? []) {
      hookedUser =
        ((await hook({ collection: config, context: req.context, req, user: hookedUser as never })) as RawUser) ||
        hookedUser
    }
    if (onSignIn) await onSignIn({ collection: collectionSlug, passkey, req, user: hookedUser })

    const { exp, token } = await jwtSign({ fieldsToSign, secret: payload.secret, tokenExpiration: auth.tokenExpiration })
    req.user = hookedUser as unknown as PayloadRequest['user']

    for (const hook of config.hooks?.afterLogin ?? []) {
      hookedUser =
        ((await hook({ collection: config, context: req.context, req, token, user: hookedUser as never })) as RawUser) ||
        hookedUser
    }

    const responseUser = await toResponseUser({ collectionSlug, req, sid, user })
    if (shouldCommit) await commitTransaction(req)

    return {
      body: {
        exp,
        message: req.t('authentication:passed'),
        ...(auth.removeTokenFromResponses ? {} : { token }),
        user: responseUser,
      },
      setCookie: cookieFor(req, config, token),
      sid,
      wasLocked,
    }
  } catch (error) {
    if (sid) {
      await revokeSessions({ collectionSlug, only: [sid], req, userId: user.id }).catch((revokeError: unknown) =>
        payload.logger.error({ err: revokeError, msg: 'passkeys: failed to revoke a session after a refused sign-in' }),
      )
    }
    await killTransaction(req)
    throw error
  }
}

/**
 * Re-authentication with the password for the fresh-session rule (review H1). Runs Payload's own
 * login operation for the signed-in user (lockout, attempt counting, beforeLogin and afterLogin
 * all apply), moves the browser onto the new session and revokes the old one.
 */
export const reauthenticate = async ({
  collectionSlug,
  password,
  previousSid,
  req,
  userId,
}: {
  collectionSlug: string
  password: string
  previousSid: string
  req: PayloadRequest
  userId: number | string
}): Promise<SessionResult> => {
  const config = authCollectionConfig(req, collectionSlug)
  const user = await loadRawUser(req, collectionSlug, userId)
  if (!user) throw new SignInRefused('user_missing')

  const result = await loginOperation({
    collection: req.payload.collections[collectionSlug as CollectionSlug],
    data: { ...loginIdentifier(config, user), password } as never,
    req,
  })
  if (!result.token) throw new SignInRefused('login_failed')
  const sid = sidFromToken(result.token)
  await revokeSessions({ collectionSlug, only: [previousSid], req, userId })

  const fresh = await loadRawUser(req, collectionSlug, userId)
  return {
    body: {
      exp: result.exp ?? 0,
      message: req.t('authentication:passed'),
      ...(config.auth.removeTokenFromResponses ? {} : { token: result.token }),
      user: await toResponseUser({ collectionSlug, req, sid, user: fresh ?? user }),
    },
    setCookie: cookieFor(req, config, result.token),
    sid,
  }
}
```

If `tsc` rejects a hook or helper argument type, cast at the call site as shown, and never change behaviour to satisfy a type.

**Step 2: Run the contract tests.**

Run `pnpm test:int test/int/mintSession.contract.int.spec.ts`. Expected: PASS (16 tests).

If "survives a password change made from itself" fails, Payload has changed the core behaviour: record it and change the expectation, not the plugin. If any revocation test fails, **stop**: the design's central assumption is wrong for that Payload version.

**Step 3: Commit.**

```bash
git add src/server/mintSession.ts
git commit -m "feat: mint native Payload sessions after a verified passkey"
```

### Task 8: Contract tests for `reauthenticate` and `revokeSessions`

> **Implemented as (2026-11-06):** the contract tests here are as planned. The wrong-account refusal described under Task 7 is pinned by a unit test with a stubbed `loginOperation`, `test/unit/reauthIdentity.spec.ts`, because it needs Payload to sign in a different account than asked.

**Files:**
- Test: `test/int/reauthenticate.contract.int.spec.ts`
- Modify: `src/server/mintSession.ts` (only if a test exposes a defect)

**Step 1: Write the tests.**

```ts
// test/int/reauthenticate.contract.int.spec.ts
import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { reauthenticate, revokeSessions } from '../../src/server/mintSession.js'
import config from '../configs/single.js'
import { cloneWithCookies, createClient } from '../helpers/api.js'
import { requestFor } from '../helpers/requests.js'
import { createUser, PASSWORD, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const signedIn = async () => {
  const user = await createUser(payload, 'users')
  const client = createClient(config)
  expect((await client.post('/api/users/login', { email: user.email, password: PASSWORD })).status).toBe(200)
  const sid = (await rawUser(payload, 'users', user.id)).sessions!.at(-1)!.id
  return { client, sid, user }
}

const reauth = async (client: ReturnType<typeof createClient>, userId: number | string, sid: string, password: string) =>
  reauthenticate({
    collectionSlug: 'users',
    password,
    previousSid: sid,
    req: await requestFor(config, '/api/users/passkeys/reauth', client),
    userId,
  })

describe('reauthenticate', () => {
  it('moves the browser to a new session and revokes the old one', async () => {
    const { client, sid, user } = await signedIn()
    const old = new Map(client.cookies)
    const result = await reauth(client, user.id, sid, PASSWORD)
    expect(result.sid).not.toBe(sid)
    const sessions = (await rawUser(payload, 'users', user.id)).sessions!.map((s) => s.id)
    expect(sessions).toContain(result.sid)
    expect(sessions).not.toContain(sid)
    expect((await cloneWithCookies(config, old).get('/api/users/me')).json.user).toBeNull()
    const fresh = createClient(config)
    fresh.setCookie(result.setCookie)
    expect((await fresh.get('/api/users/me')).json.user.id).toBe(user.id)
  })

  it('counts a wrong password towards the lockout and keeps the old session', async () => {
    const { client, sid, user } = await signedIn()
    await expect(reauth(client, user.id, sid, 'wrong password')).rejects.toThrow()
    expect((await rawUser(payload, 'users', user.id)).loginAttempts).toBe(1)
    expect((await client.get('/api/users/me')).json.user.id).toBe(user.id)
  })

  it('locks after maxLoginAttempts and then refuses the right password too', async () => {
    const { client, sid, user } = await signedIn()
    for (let i = 0; i < 5; i++) await reauth(client, user.id, sid, 'wrong').catch(() => undefined)
    await expect(reauth(client, user.id, sid, PASSWORD)).rejects.toMatchObject({ name: 'LockedAuth' })
  })
})

describe('revokeSessions', () => {
  it('keeps only the named session, or removes all', async () => {
    const user = await createUser(payload, 'users')
    for (let i = 0; i < 3; i++) {
      await createClient(config).post('/api/users/login', { email: user.email, password: PASSWORD })
    }
    const ids = (await rawUser(payload, 'users', user.id)).sessions!.map((s) => s.id)
    const req = await requestFor(config, '/api/users/passkeys/delete')
    expect(await revokeSessions({ collectionSlug: 'users', keep: ids[0], req, userId: user.id })).toBe(2)
    expect((await rawUser(payload, 'users', user.id)).sessions!.map((s) => s.id)).toEqual([ids[0]])
    expect(await revokeSessions({ collectionSlug: 'users', req, userId: user.id })).toBe(1)
    expect((await rawUser(payload, 'users', user.id)).sessions ?? []).toHaveLength(0)
  })
})
```

**Step 2: Run them.**

Run `pnpm test:int test/int/reauthenticate.contract.int.spec.ts`. Expected: PASS (4 tests).

**Step 3: Commit.**

```bash
git add test/int/reauthenticate.contract.int.spec.ts
git commit -m "test: pin password re-authentication and session revocation to Payload's behaviour"
```

### Task 9: Gate: the contract on all three adapters and every supported minor

**Files:**
- Create: `scripts/use-payload-version.mjs`

**Step 1: Write `scripts/use-payload-version.mjs`.** CI uses it to switch every Payload package to one version in a single step.

```js
// Usage: node scripts/use-payload-version.mjs 3.91.0   (or latest, beta)
import { execFileSync } from 'node:child_process'

const version = process.argv[2]
if (!version) throw new Error('Give a version, for example 3.91.0, latest or beta')
const packages = ['payload', '@payloadcms/next', '@payloadcms/ui', '@payloadcms/db-mongodb', '@payloadcms/db-postgres', '@payloadcms/db-sqlite']
execFileSync('pnpm', ['add', '-D', '--save-exact', ...packages.map((p) => `${p}@${version}`)], { stdio: 'inherit' })
```

**Step 2: Run the contract matrix locally.**

```bash
for v in 3.90.2 3.91.0 3.92.1 3.93.0; do
  node scripts/use-payload-version.mjs $v
  for a in mongo sqlite postgres; do
    DATABASE_ADAPTER=$a pnpm test:int test/int/mintSession.contract.int.spec.ts test/int/reauthenticate.contract.int.spec.ts || echo "FAILED $v $a"
  done
done
git checkout package.json pnpm-lock.yaml && pnpm install
```

Expected: no `FAILED` lines. SQLite has no transactions, so its revocation-on-throw tests prove the explicit `revokeSessions` path.

If 3.91.0 changes any helper signature, add the difference to `mintSession.ts` behind a feature check (`typeof x === 'function'`), never a version string. Record it in Verified facts.

**Step 3: Commit.**

```bash
git add scripts/use-payload-version.mjs
git commit -m "chore: add a script to run the suite against another Payload version"
```

## Milestone M2: server core

End state: every endpoint works end to end against the soft authenticator on all three adapters. The plugin validates its options at config time, and the recovery CLI and boot checks exist. No admin UI yet.

### Task 10: RP ID and origin rules (review M9)

**Files:**
- Create: `src/shared/rpid.ts`
- Test: `test/unit/rpid.spec.ts`

`src/shared/` is client-safe: no Node built-ins and no server imports, because the sign-in button uses `originMatchesRpID` too.

**Step 1: Write the failing test.**

```ts
// test/unit/rpid.spec.ts
import { describe, expect, it } from 'vitest'

import {
  isHostingPublicSuffix,
  isIpAddress,
  normaliseOrigin,
  originMatchesRpID,
  rpIDProblem,
} from '../../src/shared/rpid.js'

describe('rpIDProblem', () => {
  it.each(['example.com', 'admin.example.co.uk', 'localhost', 'my-site.vercel.app'])('accepts %s', (rpID) => {
    expect(rpIDProblem(rpID)).toBeNull()
  })
  it.each([
    ['vercel.app', 'public_suffix'],
    ['netlify.app', 'public_suffix'],
    ['pages.dev', 'public_suffix'],
    ['com', 'single_label'],
    ['127.0.0.1', 'ip_address'],
    ['[::1]', 'ip_address'],
    ['Example.com', 'not_lowercase'],
    ['example.com.', 'trailing_dot'],
    ['', 'empty'],
    ['https://example.com', 'not_a_hostname'],
  ])('refuses %s (%s)', (rpID, problem) => {
    expect(rpIDProblem(rpID)).toBe(problem)
  })
})

describe('normaliseOrigin', () => {
  it('returns scheme, host and port only', () => {
    expect(normaliseOrigin('https://example.com/')).toBe('https://example.com')
    expect(normaliseOrigin('https://example.com:8443')).toBe('https://example.com:8443')
    expect(normaliseOrigin('http://localhost:3000')).toBe('http://localhost:3000')
  })
  it.each([
    'https://example.com/admin',
    'https://example.com?x=1',
    'ftp://example.com',
    'http://example.com',
    'not a url',
  ])('refuses %s', (origin) => {
    expect(normaliseOrigin(origin)).toBeNull()
  })
})

describe('originMatchesRpID', () => {
  it('matches the RP ID itself and its subdomains only', () => {
    expect(originMatchesRpID('https://example.com', 'example.com')).toBe(true)
    expect(originMatchesRpID('https://www.example.com', 'example.com')).toBe(true)
    expect(originMatchesRpID('https://badexample.com', 'example.com')).toBe(false)
    expect(originMatchesRpID('https://example.com.evil.test', 'example.com')).toBe(false)
    expect(originMatchesRpID('https://site-git-x.vercel.app', 'example.com')).toBe(false)
    expect(originMatchesRpID('http://localhost:3000', 'localhost')).toBe(true)
    expect(originMatchesRpID('http://127.0.0.1:3000', 'localhost')).toBe(false)
  })
})

describe('helpers', () => {
  it('knows hosting suffixes and IP addresses', () => {
    expect(isHostingPublicSuffix('vercel.app')).toBe(true)
    expect(isHostingPublicSuffix('example.com')).toBe(false)
    expect(isIpAddress('10.0.0.1')).toBe(true)
    expect(isIpAddress('::1')).toBe(true)
    expect(isIpAddress('example.com')).toBe(false)
  })
})
```

Run `pnpm test:unit test/unit/rpid.spec.ts`. Expected: FAIL, "Cannot find module '../../src/shared/rpid.js'".

**Step 2: Write `src/shared/rpid.ts`, complete.**

```ts
/**
 * Hosting domains in the private section of the Public Suffix List where every customer gets a
 * subdomain. Checked against publicsuffix.org's list on 2026-11-06. An RP ID equal to one of these
 * would let every other customer's site use the passkeys, and browsers refuse it anyway.
 */
export const HOSTING_PUBLIC_SUFFIXES: readonly string[] = [
  'amplifyapp.com',
  'azurestaticapps.net',
  'azurewebsites.net',
  'cloudfront.net',
  'deno.dev',
  'firebaseapp.com',
  'fly.dev',
  'github.io',
  'gitlab.io',
  'herokuapp.com',
  'netlify.app',
  'ngrok-free.app',
  'ngrok.app',
  'onrender.com',
  'pages.dev',
  'trycloudflare.com',
  'up.railway.app',
  'vercel.app',
  'vercel.dev',
  'web.app',
  'workers.dev',
]

export type RpIDProblem =
  | 'empty'
  | 'ip_address'
  | 'not_a_hostname'
  | 'not_lowercase'
  | 'public_suffix'
  | 'single_label'
  | 'trailing_dot'

const IPV4 = /^(\d{1,3})(\.\d{1,3}){3}$/

export const isIpAddress = (host: string): boolean => {
  const bare = host.replace(/^\[|\]$/g, '')
  return IPV4.test(bare) || bare.includes(':')
}

export const isHostingPublicSuffix = (host: string): boolean => HOSTING_PUBLIC_SUFFIXES.includes(host)

/** Why a value can't be a WebAuthn RP ID, or null when it can. */
export const rpIDProblem = (rpID: string): null | RpIDProblem => {
  if (!rpID) return 'empty'
  if (isIpAddress(rpID)) return 'ip_address'
  if (!/^[a-zA-Z0-9.-]+$/.test(rpID)) return 'not_a_hostname'
  if (rpID !== rpID.toLowerCase()) return 'not_lowercase'
  if (rpID.endsWith('.')) return 'trailing_dot'
  if (!rpID.includes('.') && rpID !== 'localhost') return 'single_label'
  if (isHostingPublicSuffix(rpID)) return 'public_suffix'
  return null
}

const isLocalhost = (hostname: string): boolean =>
  hostname === 'localhost' || hostname.endsWith('.localhost')

/**
 * The origin (scheme, host, port) of a configured value, or null when it has a path, query or
 * fragment, isn't http(s), or is plain http anywhere but localhost (not a secure context).
 */
export const normaliseOrigin = (value: string): null | string => {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return null
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
  if (url.protocol === 'http:' && !isLocalhost(url.hostname)) return null
  if ((url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) return null
  if (url.username || url.password) return null
  return url.origin
}

/** True when the origin's host is the RP ID or a subdomain of it (WebAuthn L3 §5.1.4.1). */
export const originMatchesRpID = (origin: string, rpID: string): boolean => {
  let hostname: string
  try {
    hostname = new URL(origin).hostname
  } catch {
    return false
  }
  return hostname === rpID || hostname.endsWith(`.${rpID}`)
}
```

**Step 3: Run the test.** Run `pnpm test:unit test/unit/rpid.spec.ts`. Expected: PASS.

**Step 4: Commit.**

```bash
git add src/shared/rpid.ts test/unit/rpid.spec.ts
git commit -m "feat: validate RP IDs and origins"
```

### Task 11: Option resolution and config-time checks (review H4, M4, M9)

**Files:**
- Create: `src/server/options.ts`
- Modify: `src/index.ts` (re-export the real option types)
- Test: `test/unit/options.spec.ts`

`resolveOptions` runs inside the plugin function, on the **raw** config before Payload sanitises it. So `auth: true` means "all defaults", `csrf` may be undefined, and sanitize will later append `serverURL` to `csrf` when it is set (`PL/config/sanitize.js:341`).

**Step 1: Write the failing test.**

```ts
// test/unit/options.spec.ts
import type { Config } from 'payload'

import { describe, expect, it } from 'vitest'

import { PasskeysConfigError, resolveOptions } from '../../src/server/options.js'

const base = (overrides: Partial<Config> = {}): Config =>
  ({
    collections: [{ slug: 'users', auth: true, fields: [] }],
    secret: 'x',
    serverURL: 'https://example.com',
    ...overrides,
  }) as Config

describe('resolveOptions defaults', () => {
  it('derives everything from serverURL and admin.user', () => {
    const resolved = resolveOptions(base(), {})
    expect(resolved).toMatchObject({
      collections: ['users'],
      enabled: true,
      enrolmentPrompt: true,
      freshSessionMs: 600_000,
      limits: { anonymousChallenges: 500, passkeysPerUser: 20 },
      logging: { ip: 'truncated' },
      origins: ['https://example.com'],
      rateLimitIsDefault: true,
      rpID: 'example.com',
      rpName: 'example.com',
      secureCookies: true,
      slugs: { challengeUses: 'passkey-challenge-uses', challenges: 'passkey-challenges', passkeys: 'passkeys' },
    })
  })

  it('uses admin.user, then the first auth collection', () => {
    const config = base({
      admin: { user: 'admins' },
      collections: [
        { slug: 'users', auth: true, fields: [] },
        { slug: 'admins', auth: true, fields: [] },
      ],
    })
    expect(resolveOptions(config, {}).collections).toEqual(['admins'])
  })

  it('takes rpName from admin.meta.title', () => {
    expect(resolveOptions(base({ admin: { meta: { title: 'Site admin' } } }), {}).rpName).toBe('Site admin')
  })

  it('uses plain cookie names on http://localhost', () => {
    const resolved = resolveOptions(base({ serverURL: 'http://localhost:3000' }), {})
    expect(resolved).toMatchObject({ origins: ['http://localhost:3000'], rpID: 'localhost', secureCookies: false })
  })

  it('accepts several origins under the RP ID', () => {
    const resolved = resolveOptions(base(), {
      origins: ['https://example.com', 'https://www.example.com/'],
      rpID: 'example.com',
    })
    expect(resolved.origins).toEqual(['https://example.com', 'https://www.example.com'])
  })
})

describe('resolveOptions refuses impossible configs', () => {
  const refuses = (config: Config, options: Parameters<typeof resolveOptions>[1], message: RegExp) => {
    expect(() => resolveOptions(config, options)).toThrow(PasskeysConfigError)
    expect(() => resolveOptions(config, options)).toThrow(message)
  }

  it('no RP ID and no serverURL', () => refuses(base({ serverURL: undefined }), {}, /rpID/))
  it('a hosting public suffix', () => refuses(base(), { origins: ['https://vercel.app'], rpID: 'vercel.app' }, /public suffix/))
  it('an origin outside the RP ID', () =>
    refuses(base(), { origins: ['https://example.com', 'https://preview.vercel.app'], rpID: 'example.com' }, /preview\.vercel\.app/))
  it('an origin with a path', () => refuses(base(), { origins: ['https://example.com/admin'] }, /origin/))
  it('plain http off localhost', () => refuses(base({ serverURL: 'http://example.com' }), {}, /origin/))
  it('an unknown collection', () => refuses(base(), { collections: ['members'] }, /members/))
  it('a collection without auth', () =>
    refuses(base({ collections: [{ slug: 'users', auth: true, fields: [] }, { slug: 'posts', fields: [] }] }), { collections: ['posts'] }, /auth/))
  it('useSessions: false (review H4)', () =>
    refuses(base({ collections: [{ slug: 'users', auth: { useSessions: false }, fields: [] }] }), {}, /useSessions/))
  it('disableLocalStrategy', () =>
    refuses(base({ collections: [{ slug: 'users', auth: { disableLocalStrategy: true }, fields: [] }] }), {}, /disableLocalStrategy/))
  it('endpoints: false', () =>
    refuses(base({ collections: [{ slug: 'users', auth: true, endpoints: false, fields: [] }] }), {}, /endpoints/))
  it("sameSite 'None' with no csrf list (review M4)", () =>
    refuses(
      base({ collections: [{ slug: 'users', auth: { cookies: { sameSite: 'None', secure: true } }, fields: [] }], serverURL: undefined }),
      { rpID: 'example.com', origins: ['https://example.com'] },
      /csrf/,
    ))
  it('a slug that already exists', () =>
    refuses(base({ collections: [{ slug: 'users', auth: true, fields: [] }, { slug: 'passkeys', fields: [] }] }), {}, /passkeys/))
  it('limits that are not positive whole numbers', () => refuses(base(), { limits: { passkeysPerUser: 0 } }, /passkeysPerUser/))
  it('freshSessionMinutes out of range', () => refuses(base(), { freshSessionMinutes: 0 }, /freshSessionMinutes/))
})

describe('resolveOptions warnings', () => {
  it('warns when csrf will be empty', () => {
    const resolved = resolveOptions(base({ serverURL: undefined }), { origins: ['https://example.com'], rpID: 'example.com' })
    expect(resolved.warnings.join('\n')).toMatch(/csrf/)
  })
  it('does not warn about csrf when serverURL is set', () => {
    expect(resolveOptions(base(), {}).warnings.join('\n')).not.toMatch(/csrf/)
  })
})
```

Run `pnpm test:unit test/unit/options.spec.ts`. Expected: FAIL, module not found.

**Step 2: Write `src/server/options.ts`, complete.**

```ts
import type { CollectionConfig, Config, IncomingAuthType } from 'payload'

import type { OnSignInHook, PasskeysPluginOptions, RateLimitHook } from '../types.js'

import { DEFAULT_SLUGS } from '../shared/constants.js'
import { normaliseOrigin, originMatchesRpID, rpIDProblem } from '../shared/rpid.js'

export class PasskeysConfigError extends Error {
  constructor(message: string) {
    super(`[payload-passkeys] ${message}`)
    this.name = 'PasskeysConfigError'
  }
}

export type ResolvedOptions = {
  collections: string[]
  enabled: boolean
  enrolmentPrompt: boolean
  freshSessionMs: number
  limits: { anonymousChallenges: number; passkeysPerUser: number }
  logging: { ip: 'full' | 'none' | 'truncated' }
  onSignIn?: OnSignInHook
  origins: string[]
  rateLimit: RateLimitHook
  rateLimitIsDefault: boolean
  rpID: string
  rpName: string
  /** `__Host-` and `Secure` on the browser-key cookies, from the configured origins (review L7). */
  secureCookies: boolean
  slugs: { challengeUses: string; challenges: string; passkeys: string }
  /** Logged once at boot (Task 25); config time has no logger. */
  warnings: string[]
}

export const allowEverything: RateLimitHook = () => true

const authOf = (collection: CollectionConfig): IncomingAuthType | null => {
  if (!collection.auth) return null
  return collection.auth === true ? {} : collection.auth
}

const positiveInteger = (value: unknown, name: string, fallback: number): number => {
  if (value === undefined) return fallback
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw new PasskeysConfigError(`${name} must be a whole number of at least 1, not ${String(value)}.`)
  }
  return value
}

const serverURLOrigin = (serverURL: string | undefined): null | string => {
  if (!serverURL) return null
  try {
    return normaliseOrigin(new URL(serverURL).origin)
  } catch {
    return null
  }
}

export const resolveOptions = (config: Config, options: PasskeysPluginOptions): ResolvedOptions => {
  const all = config.collections ?? []
  const warnings: string[] = []

  // Collections
  const firstAuth = all.find((collection) => collection.auth)?.slug
  const collections = options.collections ?? [config.admin?.user ?? firstAuth].filter((s): s is string => !!s)
  if (collections.length === 0) {
    throw new PasskeysConfigError('No auth collection found. Pass `collections` or add an auth collection.')
  }
  for (const slug of collections) {
    const collection = all.find((c) => c.slug === slug)
    if (!collection) throw new PasskeysConfigError(`Collection "${slug}" is not in the config.`)
    const auth = authOf(collection)
    if (!auth) throw new PasskeysConfigError(`Collection "${slug}" has no auth. Passkeys need an auth collection.`)
    if (auth.disableLocalStrategy) {
      throw new PasskeysConfigError(`Collection "${slug}" sets auth.disableLocalStrategy. Passkeys mint Payload's own JWT sessions, so the local strategy must be on.`)
    }
    if (auth.useSessions === false) {
      throw new PasskeysConfigError(`Collection "${slug}" sets auth.useSessions: false. Passkeys need server-side sessions so that sign-out and revocation work.`)
    }
    if (collection.endpoints === false) {
      throw new PasskeysConfigError(`Collection "${slug}" sets endpoints: false, so it cannot host the passkey endpoints.`)
    }
  }

  // RP ID and origins (review M9)
  const fromServerURL = serverURLOrigin(config.serverURL)
  if (config.serverURL && !fromServerURL && !options.origins) {
    throw new PasskeysConfigError(`serverURL "${config.serverURL}" is not a usable origin (https, or http on localhost). Pass \`origins\`.`)
  }
  const rawOrigins = options.origins ?? (fromServerURL ? [fromServerURL] : [])
  const origins = rawOrigins.map((value) => {
    const origin = normaliseOrigin(value)
    if (!origin) {
      throw new PasskeysConfigError(`"${value}" is not a valid origin: use scheme, host and optional port only, https except on localhost.`)
    }
    return origin
  })
  const rpID = options.rpID ?? (origins[0] ? new URL(origins[0]).hostname : undefined)
  if (!rpID) {
    throw new PasskeysConfigError('Set `rpID` and `origins`, or set serverURL, so the plugin knows which domain passkeys belong to.')
  }
  if (origins.length === 0) throw new PasskeysConfigError('Set `origins` (serverURL is not set).')
  const problem = rpIDProblem(rpID)
  if (problem === 'public_suffix') {
    throw new PasskeysConfigError(`rpID "${rpID}" is a hosting public suffix; every other site on it could use your passkeys. Use your own domain.`)
  }
  if (problem) throw new PasskeysConfigError(`rpID "${rpID}" is not a valid RP ID (${problem}).`)
  for (const origin of origins) {
    if (!originMatchesRpID(origin, rpID)) {
      throw new PasskeysConfigError(`Origin ${origin} is not ${rpID} or a subdomain of it, so passkeys for ${rpID} can't work there.`)
    }
  }
  const secureCookies = origins.every((origin) => origin.startsWith('https:'))

  // CSRF (review M4). Sanitize appends serverURL to csrf, so csrf is empty only when both are.
  const csrfWillBeEmpty = (config.csrf?.length ?? 0) === 0 && !config.serverURL
  if (csrfWillBeEmpty) {
    const sameSiteNone = collections.some((slug) => {
      const auth = authOf(all.find((c) => c.slug === slug)!)
      return auth?.cookies?.sameSite === 'None'
    })
    if (sameSiteNone) {
      throw new PasskeysConfigError("auth.cookies.sameSite is 'None' and the csrf list is empty, so any site could use the session cookie. Set `csrf` to your origins.")
    }
    warnings.push(`The csrf list is empty, so Payload accepts the session cookie from any origin. Set \`csrf: ${JSON.stringify(origins)}\` in your Payload config.`)
  }

  // Slugs
  const slugs = { ...DEFAULT_SLUGS, ...options.slugs }
  for (const slug of Object.values(slugs)) {
    if (all.some((c) => c.slug === slug)) {
      throw new PasskeysConfigError(`A collection called "${slug}" already exists. Pass \`slugs\` to rename the plugin's collections.`)
    }
  }
  if (new Set(Object.values(slugs)).size !== 3) throw new PasskeysConfigError('The three slugs must differ.')

  // Numbers
  const freshSessionMinutes = positiveInteger(options.freshSessionMinutes, 'freshSessionMinutes', 10)
  if (freshSessionMinutes > 60) throw new PasskeysConfigError('freshSessionMinutes must be 60 or less.')
  const limits = {
    anonymousChallenges: positiveInteger(options.limits?.anonymousChallenges, 'limits.anonymousChallenges', 500),
    passkeysPerUser: positiveInteger(options.limits?.passkeysPerUser, 'limits.passkeysPerUser', 20),
  }
  const ip = options.logging?.ip ?? 'truncated'
  if (!['full', 'none', 'truncated'].includes(ip)) throw new PasskeysConfigError(`logging.ip must be 'none', 'truncated' or 'full'.`)

  return {
    collections,
    enabled: options.enabled ?? true,
    enrolmentPrompt: options.enrolmentPrompt ?? true,
    freshSessionMs: freshSessionMinutes * 60_000,
    limits,
    logging: { ip },
    onSignIn: options.onSignIn,
    origins,
    rateLimit: options.rateLimit ?? allowEverything,
    rateLimitIsDefault: !options.rateLimit,
    rpID,
    rpName: options.rpName ?? config.admin?.meta?.title ?? rpID,
    secureCookies,
    slugs,
    warnings,
  }
}
```

`admin.meta.title` is typed `string | undefined` on `MetaConfig`; if `tsc` disagrees on the installed minor, read it through `(config.admin?.meta as { title?: string } | undefined)?.title`.

**Step 3: Re-export the types.** In `src/index.ts`, delete the stub `PasskeysPluginOptions` type and add `export type * from './types.js'`. The plugin body stays a no-op until Task 13.

**Step 4: Run the tests.** Run `pnpm test:unit test/unit/options.spec.ts`. Expected: PASS. Enable the commented-out `limits` in `test/configs/*.ts` and `onSignIn` in `dev/buildConfig.ts`, then run `pnpm typecheck`. Expected: no errors.

**Step 5: Commit.**

```bash
git add src/server/options.ts src/index.ts test/unit/options.spec.ts test/configs dev/buildConfig.ts
git commit -m "feat: resolve plugin options and refuse impossible configs at boot"
```

### Task 12: Post-sign-in redirect (review L5)

> **Implemented as (2026-11-06):** `safeAdminRedirect` also refuses a resolved path that starts with `//` or `/\`: resolving dot segments can turn `/.//evil.test` into `//evil.test`, which `getSafeRedirect` only checks before resolution.

**Files:**
- Create: `src/shared/redirect.ts`
- Test: `test/unit/redirect.spec.ts`

**Step 1: Write the failing test.**

```ts
// test/unit/redirect.spec.ts
import { describe, expect, it } from 'vitest'

import { safeAdminRedirect } from '../../src/shared/redirect.js'

describe('safeAdminRedirect', () => {
  it.each([
    ['/admin', '/admin'],
    ['/admin/collections/posts?where=1#top', '/admin/collections/posts?where=1#top'],
    ['/admin/', '/admin/'],
  ])('keeps %s', (input, expected) => {
    expect(safeAdminRedirect(input, '/admin')).toBe(expected)
  })

  it.each([
    undefined,
    null,
    42,
    '',
    'https://evil.test/admin',
    '//evil.test/admin',
    '/\\evil.test',
    '/%2F%2Fevil.test',
    '/javascript:alert(1)',
    '/api/users/me',
    '/administrator',
    '/admin/../api/users',
    '/admin/%2e%2e/api/users',
    '/admin\n/x',
    ' /admin@evil.test',
  ])('sends %j to the admin root', (input) => {
    expect(safeAdminRedirect(input, '/admin')).toBe('/admin')
  })

  it('respects a custom admin route', () => {
    expect(safeAdminRedirect('/cms/collections/pages', '/cms')).toBe('/cms/collections/pages')
    expect(safeAdminRedirect('/admin', '/cms')).toBe('/cms')
    expect(safeAdminRedirect('/anything', '/')).toBe('/anything')
  })
})
```

Run `pnpm test:unit test/unit/redirect.spec.ts`. Expected: FAIL, module not found.

**Step 2: Write `src/shared/redirect.ts`, complete.**

```ts
import { getSafeRedirect } from 'payload/shared'

const normaliseAdminRoute = (adminRoute: string): string => {
  const trimmed = adminRoute.replace(/^\/+|\/+$/g, '')
  return trimmed ? `/${trimmed}` : '/'
}

/**
 * Where to go after a passkey sign-in. Payload's own getSafeRedirect rules out other origins and
 * the known tricks; on top of that the WHATWG parser resolves dot segments (including %2e%2e), and
 * the result must sit under the admin route, so the `redirect` parameter can't send a freshly
 * signed-in admin anywhere else on the site (review L5).
 */
export const safeAdminRedirect = (redirectTo: unknown, adminRoute = '/admin'): string => {
  const admin = normaliseAdminRoute(adminRoute)
  const safe = getSafeRedirect({ fallbackTo: admin, redirectTo: typeof redirectTo === 'string' ? redirectTo : '' })
  if (safe === admin) return admin
  let url: URL
  try {
    url = new URL(safe, 'http://localhost')
  } catch {
    return admin
  }
  if (url.origin !== 'http://localhost' || url.username || url.password) return admin
  const { hash, pathname, search } = url
  const inside = admin === '/' || pathname === admin || pathname.startsWith(`${admin}/`)
  return inside ? `${pathname}${search}${hash}` : admin
}
```

**Step 3: Run the test.** Run `pnpm test:unit test/unit/redirect.spec.ts`. Expected: PASS. (`' /admin@evil.test'` is trimmed by `getSafeRedirect` to the path `/admin@evil.test`, which is not under `/admin/`, so it falls back.)

**Step 4: Commit.**

```bash
git add src/shared/redirect.ts test/unit/redirect.spec.ts
git commit -m "feat: restrict post-sign-in redirects to admin paths"
```

### Task 13: Collections, user fields and plugin wiring (review H3, L3)

> **Implemented as (2026-11-06):** the stored slug field is `authCollection` on both `passkeys` and `passkey-challenges`, and the access and `where` clauses use it. Passkeys and pending challenges are removed from a **`beforeDelete`** hook, not `afterDelete`: on SQL the user row can't be deleted first (`passkeys.user_id` is `NOT NULL`, and polymorphic `_rels` rows cascade away before `afterDelete` runs). Errors propagate. Caveat: Payload checks the document lock after `beforeDelete`, so on an adapter without transactions a delete refused for a lock has already removed the passkeys (fails safe; logged as `passkeys.removed`, `reason: user_deleted`). The helper `ownerField` builds `user`.

**Files:**
- Create: `src/collections/passkeys.ts`, `src/collections/challenges.ts`, `src/collections/challengeUses.ts`, `src/collections/userFields.ts`, `src/server/context.ts`, `src/server/endpoints/index.ts`, `test/helpers/passkeys.ts`
- Modify: `src/index.ts`
- Test: `test/int/schema.int.spec.ts`

**Step 1: Write the failing test.**

```ts
// test/int/schema.int.spec.ts
import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import config from '../configs/multi.js'
import { createClient } from '../helpers/api.js'
import { insertPasskey } from '../helpers/passkeys.js'
import { findSecretKeys } from '../helpers/secrets.js'
import { createUser, PASSWORD } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const signIn = async (collection: 'customers' | 'users', email: string) => {
  const client = createClient(config)
  expect((await client.post(`/api/${collection}/login`, { email, password: PASSWORD })).status).toBe(200)
  return client
}

describe('plugin collections', () => {
  it('are hidden, unlocked and out of GraphQL', () => {
    for (const slug of ['passkeys', 'passkey-challenges', 'passkey-challenge-uses'] as const) {
      const { config: collection } = payload.collections[slug]
      expect(collection.admin.hidden).toBe(true)
      expect(collection.graphQL).toBe(false)
      expect(collection.lockDocuments).toBe(false)
    }
  })

  it('make the passkey owner polymorphic when two collections are configured', () => {
    const user = payload.collections.passkeys.config.fields.find((f) => 'name' in f && f.name === 'user')
    expect(user).toMatchObject({ maxDepth: 0, relationTo: ['users', 'customers'], type: 'relationship' })
  })
})

describe('passkeys access (review H3)', () => {
  it('lets a user read only their own passkeys, with no key material', async () => {
    const alice = await createUser(payload, 'users')
    const bob = await createUser(payload, 'users')
    await insertPasskey(payload, { collection: 'users', userId: alice.id })
    await insertPasskey(payload, { collection: 'users', userId: bob.id })
    const list = await (await signIn('users', alice.email)).get('/api/passkeys?depth=0&limit=100')
    expect(list.status).toBe(200)
    expect(list.json.docs).toHaveLength(1)
    expect(list.json.docs[0].collection).toBe('users')
    expect(findSecretKeys(list.json)).toEqual([])
  })

  it('refuses REST create, update and delete even for the owner', async () => {
    const alice = await createUser(payload, 'users')
    const row = await insertPasskey(payload, { collection: 'users', userId: alice.id })
    const client = await signIn('users', alice.email)
    expect((await client.post('/api/passkeys', { name: 'x' })).status).toBe(403)
    expect((await client.patch(`/api/passkeys/${row.id}`, { name: 'x' })).status).toBe(403)
    expect((await client.delete(`/api/passkeys/${row.id}`)).status).toBe(403)
  })

  it('refuses every API read of challenges and uses', async () => {
    const alice = await createUser(payload, 'users')
    const client = await signIn('users', alice.email)
    expect((await client.get('/api/passkey-challenges')).status).toBe(403)
    expect((await client.get('/api/passkey-challenge-uses')).status).toBe(403)
  })
})

describe('user fields', () => {
  it('never shows passkeyUserHandle, even to its owner', async () => {
    const alice = await createUser(payload, 'users')
    await payload.db.updateOne({ collection: 'users', data: { passkeyUserHandle: 'h'.repeat(86) }, id: alice.id, returning: false })
    const me = await (await signIn('users', alice.email)).get('/api/users/me')
    expect(me.json.user.passkeyUserHandle).toBeUndefined()
  })

  it("deletes a user's passkeys with the user", async () => {
    const alice = await createUser(payload, 'users')
    await insertPasskey(payload, { collection: 'users', userId: alice.id })
    await payload.delete({ collection: 'users', id: alice.id })
    const left = await payload.count({ collection: 'passkeys', where: { collection: { equals: 'users' }, 'user.value': { equals: alice.id } } })
    expect(left.totalDocs).toBe(0)
  })
})
```

Write `test/helpers/passkeys.ts`:

```ts
import type { Payload } from 'payload'

import { randomBytes } from 'crypto'

/** Inserts a passkey row directly (no ceremony), for access and schema tests. */
export const insertPasskey = async (
  payload: Payload,
  { collection, userId, ...data }: { collection: string; userId: number | string } & Record<string, unknown>,
) => {
  const polymorphic = Array.isArray(
    (payload.collections.passkeys.config.fields.find((f) => 'name' in f && f.name === 'user') as { relationTo: unknown })
      .relationTo,
  )
  return (await payload.create({
    collection: 'passkeys',
    data: {
      backedUp: true,
      collection,
      counter: 0,
      credentialId: randomBytes(16).toString('base64url'),
      deviceType: 'multiDevice',
      name: 'Test passkey',
      publicKey: randomBytes(77).toString('base64url'),
      rpID: 'localhost',
      transports: ['internal'],
      user: polymorphic ? { relationTo: collection, value: userId } : userId,
      userHandle: randomBytes(64).toString('base64url'),
      ...data,
    },
    overrideAccess: true,
  } as never)) as { credentialId: string; id: number | string }
}
```

Run `pnpm test:int test/int/schema.int.spec.ts`. Expected: FAIL, `payload.collections.passkeys` is undefined.

**Step 2: Write `src/collections/passkeys.ts`, complete.**

```ts
import type { Access, CollectionConfig, Where } from 'payload'

import type { ResolvedOptions } from '../server/options.js'

import { MAX_PASSKEY_NAME } from '../shared/constants.js'

const never = () => false

/** Own passkeys only, matching collection and ID together: IDs collide across SQL tables (H3). */
export const ownPasskeysWhere = (options: ResolvedOptions, collection: string, id: number | string): Where => ({
  and: [
    { collection: { equals: collection } },
    options.collections.length === 1
      ? { user: { equals: id } }
      : { and: [{ 'user.relationTo': { equals: collection } }, { 'user.value': { equals: id } }] },
  ],
})

const readOwn =
  (options: ResolvedOptions): Access =>
  ({ req: { user } }) => {
    if (!user || !options.collections.includes(user.collection)) return false
    return ownPasskeysWhere(options, user.collection, user.id)
  }

export const passkeysCollection = (options: ResolvedOptions): CollectionConfig => ({
  slug: options.slugs.passkeys,
  access: { create: never, delete: never, read: readOwn(options), update: never },
  admin: { hidden: true, useAsTitle: 'name' },
  fields: [
    {
      name: 'user',
      type: 'relationship',
      index: true,
      maxDepth: 0,
      relationTo: options.collections.length === 1 ? options.collections[0]! : options.collections,
      required: true,
    },
    // The owner's collection slug, checked before anything else (H3).
    { name: 'collection', type: 'text', index: true, required: true },
    { name: 'credentialId', type: 'text', required: true, unique: true },
    // The WebAuthn user.id this passkey was made with (L4). Compared with each assertion.
    { name: 'userHandle', type: 'text', access: { read: never }, required: true },
    { name: 'publicKey', type: 'text', access: { read: never }, required: true },
    { name: 'counter', type: 'number', access: { read: never }, defaultValue: 0, required: true },
    { name: 'transports', type: 'json' },
    {
      name: 'deviceType',
      type: 'select',
      options: ['singleDevice', 'multiDevice'],
      required: true,
    },
    { name: 'backedUp', type: 'checkbox', defaultValue: false },
    { name: 'aaguid', type: 'text' },
    { name: 'rpID', type: 'text', required: true },
    { name: 'name', type: 'text', maxLength: MAX_PASSKEY_NAME, required: true },
    { name: 'lastUsedAt', type: 'date' },
  ],
  graphQL: false,
  lockDocuments: false,
  timestamps: true,
})
```

**Step 3: Write the two challenge collections, complete.**

```ts
// src/collections/challenges.ts
import type { CollectionConfig } from 'payload'

import type { ResolvedOptions } from '../server/options.js'

const never = () => false

export const challengesCollection = (options: ResolvedOptions): CollectionConfig => ({
  slug: options.slugs.challenges,
  access: { create: never, delete: never, read: never, update: never },
  admin: { hidden: true },
  fields: [
    { name: 'challenge', type: 'text', required: true, unique: true },
    { name: 'type', type: 'select', index: true, options: ['registration', 'authentication'], required: true },
    { name: 'collection', type: 'text', required: true },
    // Stored as text, not a relationship: the owner may be in any configured collection.
    { name: 'userId', type: 'text', index: true },
    { name: 'userHandle', type: 'text' },
    { name: 'browserKeyHash', type: 'text', index: true, required: true },
    { name: 'expiresAt', type: 'date', index: true, required: true },
  ],
  graphQL: false,
  lockDocuments: false,
  timestamps: true,
})
```

```ts
// src/collections/challengeUses.ts
import type { CollectionConfig } from 'payload'

import type { ResolvedOptions } from '../server/options.js'

const never = () => false

/**
 * Consuming a challenge is a unique insert here. A unique-constraint error means the challenge was
 * already used. Atomic on every adapter, unlike find-then-delete on Drizzle (review M3).
 */
export const challengeUsesCollection = (options: ResolvedOptions): CollectionConfig => ({
  slug: options.slugs.challengeUses,
  access: { create: never, delete: never, read: never, update: never },
  admin: { hidden: true },
  fields: [
    { name: 'challenge', type: 'text', required: true, unique: true },
    { name: 'expiresAt', type: 'date', index: true, required: true },
  ],
  graphQL: false,
  lockDocuments: false,
  timestamps: true,
})
```

**Step 4: Write `src/collections/userFields.ts`, complete.** The `ui` field is added in Task 28, when its component exists; until then this adds only the handle field and the clean-up hook.

```ts
import type { CollectionAfterDeleteHook, CollectionConfig, Field } from 'payload'

import type { ResolvedOptions } from '../server/options.js'

import { ownPasskeysWhere } from './passkeys.js'
import { USER_HANDLE_FIELD } from '../shared/constants.js'

const never = () => false

/** The WebAuthn user.id: 64 random bytes, base64url. Not unique (Mongo sparse indexes collide on null). */
export const userHandleField: Field = {
  name: USER_HANDLE_FIELD,
  type: 'text',
  access: { create: never, read: never, update: never },
  admin: { disabled: true, hidden: true },
}

const removePasskeysOfDeletedUser =
  (options: ResolvedOptions, collectionSlug: string): CollectionAfterDeleteHook =>
  async ({ id, req }) => {
    try {
      await req.payload.db.deleteMany({
        collection: options.slugs.passkeys,
        req,
        where: ownPasskeysWhere(options, collectionSlug, id),
      })
      await req.payload.db.deleteMany({
        collection: options.slugs.challenges,
        req,
        where: { and: [{ collection: { equals: collectionSlug } }, { userId: { equals: String(id) } }] },
      })
    } catch (error) {
      req.payload.logger.error({ err: error, msg: 'passkeys: failed to remove the passkeys of a deleted user' })
    }
  }

export const withPasskeyFields = (
  collection: CollectionConfig,
  options: ResolvedOptions,
  extraFields: Field[] = [],
): CollectionConfig => ({
  ...collection,
  fields: [...collection.fields, userHandleField, ...extraFields],
  hooks: {
    ...collection.hooks,
    afterDelete: [...(collection.hooks?.afterDelete ?? []), removePasskeysOfDeletedUser(options, collection.slug)],
  },
})
```

**Step 5: Write `src/server/context.ts`, `src/server/endpoints/index.ts` (empty for now) and wire `src/index.ts`.**

The resolved options are kept on `config.custom`, which stays on the server (the client config carries only `admin.custom`), so the CLI, boot checks and tests can read them.

```ts
// src/server/context.ts
import type { Payload, SanitizedConfig } from 'payload'

import type { ResolvedOptions } from './options.js'

import { PACKAGE_NAME } from '../shared/constants.js'

export const OPTIONS_KEY = PACKAGE_NAME

export const getPasskeysOptions = (payloadOrConfig: Payload | SanitizedConfig): ResolvedOptions => {
  const config = 'config' in payloadOrConfig ? payloadOrConfig.config : payloadOrConfig
  const options = (config.custom as Record<string, unknown> | undefined)?.[OPTIONS_KEY]
  if (!options) throw new Error(`[payload-passkeys] The plugin is not in this Payload config.`)
  return options as ResolvedOptions
}
```

```ts
// src/server/endpoints/index.ts
import type { Endpoint } from 'payload'

import type { ResolvedOptions } from '../options.js'

/** Grows one endpoint per task (Tasks 18 to 21). */
export const passkeyEndpoints = (_options: ResolvedOptions, _collectionSlug: string): Endpoint[] => []
```

```ts
// src/index.ts
import type { Config } from 'payload'

import type { PasskeysPluginOptions } from './types.js'

import { challengesCollection } from './collections/challenges.js'
import { challengeUsesCollection } from './collections/challengeUses.js'
import { passkeysCollection } from './collections/passkeys.js'
import { withPasskeyFields } from './collections/userFields.js'
import { OPTIONS_KEY } from './server/context.js'
import { passkeyEndpoints } from './server/endpoints/index.js'
import { resolveOptions } from './server/options.js'

export type * from './types.js'

export const passkeysPlugin =
  (options: PasskeysPluginOptions = {}) =>
  (incoming: Config): Config => {
    const resolved = resolveOptions(incoming, options)
    const collections = (incoming.collections ?? []).map((collection) => {
      if (!resolved.collections.includes(collection.slug)) return collection
      const withFields = withPasskeyFields(collection, resolved)
      if (!resolved.enabled) return withFields
      return {
        ...withFields,
        endpoints: [...(collection.endpoints || []), ...passkeyEndpoints(resolved, collection.slug)],
      }
    })
    return {
      ...incoming,
      collections: [
        ...collections,
        passkeysCollection(resolved),
        challengesCollection(resolved),
        challengeUsesCollection(resolved),
      ],
      custom: { ...incoming.custom, [OPTIONS_KEY]: resolved },
    }
  }
```

`enabled: false` still adds the collections and fields, so turning the plugin off never drops a SQL table or orphans data (design §3).

**Step 6: Run the tests.** Run `pnpm test:int test/int/schema.int.spec.ts`. Expected: PASS (7 tests). Then on SQLite and Postgres. Expected: PASS.

**Step 7: Commit.**

```bash
git add src/collections src/server/context.ts src/server/endpoints/index.ts src/index.ts test/helpers/passkeys.ts test/int/schema.int.spec.ts
git commit -m "feat: add the passkeys and challenge collections and the user handle field"
```

### Task 14: Request guards, cookies, IPs, logging and the rate-limit hook (review M4, L1, L2, L7)

> **Implemented as (2026-11-06):** `readJsonBody` doesn't call `addDataAndFileToRequest`. It keeps the exact `application/json` check, reads the body with its own bounded reader (64 KB, `MAX_BODY_BYTES`, enforced while streaming, not only from `Content-Length`), and sets `req.data` and `req.json` so hooks that call `req.json()` still work.

**Files:**
- Create: `src/server/http.ts`, `src/server/cookies.ts`, `src/server/ip.ts`, `src/server/logging.ts`, `src/server/rateLimit.ts`
- Modify: `src/shared/constants.ts` (add `'server_error'` and `'unsupported_media_type'` to `PasskeysErrorCode`)
- Test: `test/unit/http.spec.ts`, `test/unit/ip.spec.ts`, `test/unit/cookies.spec.ts`

**Step 1: Write the failing unit tests.**

```ts
// test/unit/ip.spec.ts
import { describe, expect, it } from 'vitest'

import { clientIp, formatIp } from '../../src/server/ip.js'

const headers = (h: Record<string, string>) => ({ headers: new Headers(h) }) as never

describe('clientIp', () => {
  it('prefers x-real-ip, then the first x-forwarded-for entry', () => {
    expect(clientIp(headers({ 'x-real-ip': '203.0.113.9', 'x-forwarded-for': '198.51.100.1' }))).toBe('203.0.113.9')
    expect(clientIp(headers({ 'x-forwarded-for': '198.51.100.1, 10.0.0.1' }))).toBe('198.51.100.1')
    expect(clientIp(headers({}))).toBeNull()
  })
})

describe('formatIp', () => {
  it('truncates IPv4 to /24 and IPv6 to /48', () => {
    expect(formatIp('203.0.113.9', 'truncated')).toBe('203.0.113.0/24')
    expect(formatIp('2001:db8:85a3:8d3:1319:8a2e:370:7348', 'truncated')).toBe('2001:db8:85a3::/48')
    expect(formatIp('2001:db8::1', 'truncated')).toBe('2001:db8:0::/48')
    expect(formatIp('::ffff:203.0.113.9', 'truncated')).toBe('203.0.113.0/24')
  })
  it('honours none and full', () => {
    expect(formatIp('203.0.113.9', 'none')).toBeUndefined()
    expect(formatIp('203.0.113.9', 'full')).toBe('203.0.113.9')
    expect(formatIp(null, 'full')).toBeUndefined()
    expect(formatIp('garbage', 'truncated')).toBeUndefined()
  })
})
```

```ts
// test/unit/cookies.spec.ts
import { describe, expect, it } from 'vitest'

import { browserKeyCookie, browserKeyCookieName, clearBrowserKeyCookie } from '../../src/server/cookies.js'

describe('browser-key cookies (review L7)', () => {
  it('use __Host- and Secure only for https origins, one name per ceremony and collection', () => {
    expect(browserKeyCookieName('authentication', 'users', true)).toBe('__Host-payload-passkeys-auth-users')
    expect(browserKeyCookieName('registration', 'users', false)).toBe('payload-passkeys-reg-users')
  })
  it('are HttpOnly, SameSite=Strict, Path=/, no Domain, Max-Age=300', () => {
    const line = browserKeyCookie('__Host-payload-passkeys-auth-users', 'k', true)
    expect(line).toBe('__Host-payload-passkeys-auth-users=k; Path=/; Max-Age=300; HttpOnly; SameSite=Strict; Secure')
    expect(line).not.toMatch(/Domain/i)
    expect(clearBrowserKeyCookie('payload-passkeys-reg-users', false)).toBe(
      'payload-passkeys-reg-users=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict',
    )
  })
})
```

```ts
// test/unit/http.spec.ts
import { describe, expect, it } from 'vitest'

import { EndpointError, originAllowed, readJsonBody, requireSignedIn } from '../../src/server/http.js'

const req = (init: { body?: string; headers?: Record<string, string>; user?: unknown }) => {
  const request = new Request('http://localhost:3000/api/users/passkeys/x', {
    body: init.body,
    headers: init.headers,
    method: 'POST',
  })
  return Object.assign(request, { payload: { config: { cookiePrefix: 'payload' } }, user: init.user ?? null }) as never
}

describe('readJsonBody (review M4)', () => {
  it('parses an application/json object', async () => {
    expect(await readJsonBody(req({ body: '{"a":1}', headers: { 'Content-Type': 'application/json' } }))).toEqual({ a: 1 })
    expect(await readJsonBody(req({ body: '{}', headers: { 'Content-Type': 'application/json; charset=utf-8' } }))).toEqual({})
  })
  it.each(['multipart/form-data; boundary=x', 'text/plain', 'application/x-www-form-urlencoded', ''])(
    'refuses %j with 415',
    async (type) => {
      const error = await readJsonBody(req({ body: '_payload={}', headers: type ? { 'Content-Type': type } : {} })).catch((e) => e)
      expect(error).toBeInstanceOf(EndpointError)
      expect(error).toMatchObject({ code: 'unsupported_media_type', status: 415 })
    },
  )
  it('refuses arrays, invalid JSON and large bodies with 400 or 413', async () => {
    const json = { 'Content-Type': 'application/json' }
    await expect(readJsonBody(req({ body: '[1]', headers: json }))).rejects.toMatchObject({ status: 400 })
    await expect(readJsonBody(req({ body: '{', headers: json }))).rejects.toMatchObject({ status: 400 })
    await expect(
      readJsonBody(req({ body: '{}', headers: { ...json, 'Content-Length': String(65 * 1024) } })),
    ).rejects.toMatchObject({ status: 413 })
  })
})

describe('originAllowed (review M4)', () => {
  const origins = ['https://example.com']
  it('accepts a listed Origin, else Sec-Fetch-Site: same-origin', () => {
    expect(originAllowed(req({ headers: { Origin: 'https://example.com' } }), origins)).toBe(true)
    expect(originAllowed(req({ headers: { Origin: 'https://evil.test' } }), origins)).toBe(false)
    expect(originAllowed(req({ headers: { Origin: 'null' } }), origins)).toBe(false)
    expect(originAllowed(req({ headers: { 'Sec-Fetch-Site': 'same-origin' } }), origins)).toBe(true)
    expect(originAllowed(req({ headers: { 'Sec-Fetch-Site': 'same-site' } }), origins)).toBe(false)
    expect(originAllowed(req({ headers: {} }), origins)).toBe(false)
  })
})

describe('requireSignedIn (review L2)', () => {
  const cookie = { Cookie: 'payload-token=t' }
  const ok = { _sid: 's', _strategy: 'local-jwt', collection: 'users', id: 1 }
  it('accepts a cookie session of this collection', () => {
    expect(requireSignedIn(req({ headers: cookie, user: ok }), 'users')).toBe(ok)
  })
  it.each([
    ['no user', {}],
    ['another collection', { headers: cookie, user: { ...ok, collection: 'customers' } }],
    ['an API key', { headers: cookie, user: { ...ok, _strategy: 'api-key' } }],
    ['no session id', { headers: cookie, user: { ...ok, _sid: undefined } }],
    ['a JWT in the Authorization header', { headers: { ...cookie, Authorization: 'JWT t' }, user: ok }],
    ['no session cookie', { headers: {}, user: ok }],
  ])('refuses %s', (_, init) => {
    expect(() => requireSignedIn(req(init as never), 'users')).toThrow(EndpointError)
  })
})
```

Run `pnpm test:unit test/unit/ip.spec.ts test/unit/cookies.spec.ts test/unit/http.spec.ts`. Expected: FAIL, modules not found.

**Step 2: Write `src/server/ip.ts`, complete.**

```ts
import type { PayloadRequest } from 'payload'

import { isIP } from 'net'

/**
 * The caller's IP from proxy headers. Only meaningful behind a proxy that sets these itself
 * (Vercel, Cloudflare, a configured load balancer); otherwise the client chooses it (README).
 */
export const clientIp = (req: Pick<PayloadRequest, 'headers'>): null | string => {
  const real = req.headers.get('x-real-ip')?.trim()
  if (real) return real
  const forwarded = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
  return forwarded || null
}

const expandIPv6 = (ip: string): null | string[] => {
  const [head = '', tail = ''] = ip.split('::')
  const left = head ? head.split(':') : []
  const right = ip.includes('::') ? (tail ? tail.split(':') : []) : []
  const fill = ip.includes('::') ? 8 - left.length - right.length : 0
  const groups = [...left, ...Array<string>(Math.max(fill, 0)).fill('0'), ...right]
  return groups.length === 8 ? groups : null
}

/** An IP for a failure log line (review L1). Never call this on a success path. */
export const formatIp = (ip: null | string, mode: 'full' | 'none' | 'truncated'): string | undefined => {
  if (!ip || mode === 'none') return undefined
  const mapped = ip.startsWith('::ffff:') && isIP(ip.slice(7)) === 4 ? ip.slice(7) : ip
  const version = isIP(mapped)
  if (version === 0) return undefined
  if (mode === 'full') return mapped
  if (version === 4) return `${mapped.split('.').slice(0, 3).join('.')}.0/24`
  const groups = expandIPv6(mapped)
  if (!groups) return undefined
  return `${groups.slice(0, 3).map((g) => g.replace(/^0+(?=.)/, '')).join(':')}::/48`
}
```

**Step 3: Write `src/server/cookies.ts`, complete.**

```ts
import type { PayloadRequest } from 'payload'

import { parseCookies } from 'payload/shared'

import { CHALLENGE_TTL_MS } from '../shared/constants.js'

export type CeremonyType = 'authentication' | 'registration'

/**
 * One cookie per ceremony type and collection, so two tabs (or a sign-in and a registration)
 * never overwrite each other. `__Host-` and Secure follow the configured origins' scheme, never
 * req.url, which reads http behind a TLS-terminating proxy (review L7).
 */
export const browserKeyCookieName = (type: CeremonyType, collection: string, secure: boolean): string =>
  `${secure ? '__Host-' : ''}payload-passkeys-${type === 'registration' ? 'reg' : 'auth'}-${collection}`

const attributes = (maxAge: number, secure: boolean): string =>
  `Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}`

export const browserKeyCookie = (name: string, value: string, secure: boolean): string =>
  `${name}=${value}; ${attributes(CHALLENGE_TTL_MS / 1000, secure)}`

export const clearBrowserKeyCookie = (name: string, secure: boolean): string => `${name}=; ${attributes(0, secure)}`

export const readCookie = (req: Pick<PayloadRequest, 'headers'>, name: string): string | undefined =>
  parseCookies(req.headers).get(name) || undefined
```

**Step 4: Write `src/server/http.ts`, complete.**

```ts
import type { PayloadRequest, TypedUser } from 'payload'

import { addDataAndFileToRequest, headersWithCors } from 'payload'
import { parseCookies } from 'payload/shared'

import type { PasskeysErrorCode } from '../shared/constants.js'

/** Registration responses are a few KB; anything bigger is not a WebAuthn response. */
export const MAX_BODY_BYTES = 64 * 1024

export class EndpointError extends Error {
  readonly code: PasskeysErrorCode
  readonly status: number
  constructor(status: number, code: PasskeysErrorCode) {
    super(code)
    this.name = 'EndpointError'
    this.code = code
    this.status = status
  }
}

export const json = (req: PayloadRequest, status: number, body: unknown, setCookies: string[] = []): Response => {
  const headers = headersWithCors({
    headers: new Headers({ 'Cache-Control': 'no-store', 'Content-Type': 'application/json' }),
    req,
  })
  for (const line of setCookies) headers.append('Set-Cookie', line)
  return new Response(JSON.stringify(body), { headers, status })
}

/**
 * The JSON body, or a refusal. Exactly `application/json` before any `;`, the same test Payload's
 * parser uses, so multipart and its `_payload` field never reach an endpoint (review M4).
 */
export const readJsonBody = async (req: PayloadRequest): Promise<Record<string, unknown>> => {
  const [type = ''] = (req.headers.get('Content-Type') ?? '').split(';', 1)
  if (type.trim() !== 'application/json') throw new EndpointError(415, 'unsupported_media_type')
  if (Number(req.headers.get('Content-Length') ?? 0) > MAX_BODY_BYTES) throw new EndpointError(413, 'bad_request')
  try {
    await addDataAndFileToRequest(req)
  } catch {
    throw new EndpointError(400, 'bad_request')
  }
  const data: unknown = req.data ?? {}
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new EndpointError(400, 'bad_request')
  return data as Record<string, unknown>
}

/** Origin in the configured list, or, with no Origin header, Sec-Fetch-Site: same-origin (M4). */
export const originAllowed = (req: Pick<PayloadRequest, 'headers'>, origins: string[]): boolean => {
  const origin = req.headers.get('Origin')
  if (origin !== null) return origins.includes(origin)
  return req.headers.get('Sec-Fetch-Site') === 'same-origin'
}

export type SignedInUser = TypedUser & { _sid: string; _strategy: 'local-jwt'; collection: string; id: number | string }

/**
 * A cookie session of this collection (L2). API keys and other strategies are refused, and so is
 * a JWT sent in the Authorization header: Payload's extractJWT reads the header before the cookie,
 * so a header token would otherwise pass as `local-jwt` with a `sid`.
 */
export const requireSignedIn = (
  req: Pick<PayloadRequest, 'headers' | 'payload' | 'user'>,
  collectionSlug: string,
): SignedInUser => {
  const user = req.user as (Partial<SignedInUser> & Record<string, unknown>) | null
  if (!user || user.collection !== collectionSlug) throw new EndpointError(401, 'unauthorised')
  const cookieName = `${req.payload.config.cookiePrefix}-token`
  if (
    user._strategy !== 'local-jwt' ||
    typeof user._sid !== 'string' ||
    !user._sid ||
    req.headers.get('Authorization') !== null ||
    !parseCookies(req.headers).get(cookieName)
  ) {
    throw new EndpointError(403, 'unauthorised')
  }
  return user as SignedInUser
}
```

`addDataAndFileToRequest` re-checks the type itself and only then calls `req.text()`. The unit test's fake request has no `payload.config.bodyParser`, which the JSON branch never reads. If the installed minor's `readJsonBody` test fails on `headersWithCors` or `addDataAndFileToRequest` needing more of `req.payload`, extend the fake in the test, not the module.

**Step 5: Write `src/server/logging.ts` and `src/server/rateLimit.ts`, complete.**

```ts
// src/server/logging.ts
import type { PayloadRequest } from 'payload'

import type { ResolvedOptions } from './options.js'

import { clientIp, formatIp } from './ip.js'

export type PasskeyEvent =
  | 'passkeys.counter_regression'
  | 'passkeys.reauth_failed'
  | 'passkeys.reauth_required'
  | 'passkeys.reauthenticated'
  | 'passkeys.registered'
  | 'passkeys.registration_failed'
  | 'passkeys.removed'
  | 'passkeys.renamed'
  | 'passkeys.sign_in_failed'
  | 'passkeys.signed_in'
  | 'passkeys.signed_in_while_locked'
  | 'passkeys.unknown_credential'

const FAILURES = new Set<PasskeyEvent>([
  'passkeys.reauth_failed',
  'passkeys.registration_failed',
  'passkeys.sign_in_failed',
  'passkeys.unknown_credential',
])

export type EventFields = {
  aaguid?: null | string
  collection: string
  credentialId?: string
  reason?: string
  userId?: number | string
}

/**
 * One structured line per event. Never challenges, signatures, public keys, user handles or
 * emails; a credential ID is cut to 8 characters; an IP only on failures and as `logging.ip` says.
 */
export const logEvent = (
  req: PayloadRequest,
  options: Pick<ResolvedOptions, 'logging'>,
  event: PasskeyEvent,
  { credentialId, ...fields }: EventFields,
): void => {
  const failure = FAILURES.has(event)
  const line: Record<string, unknown> = { event, ...fields }
  if (credentialId) line.credentialIdPrefix = credentialId.slice(0, 8)
  if (failure) {
    const ip = formatIp(clientIp(req), options.logging.ip)
    if (ip) line.ip = ip
  }
  const level = failure || event === 'passkeys.counter_regression' ? 'warn' : 'info'
  req.payload.logger[level]({ ...line, msg: event })
}
```

```ts
// src/server/rateLimit.ts
import type { PayloadRequest } from 'payload'

import type { PasskeyAction } from '../types.js'
import type { ResolvedOptions } from './options.js'

import { clientIp } from './ip.js'

/** True to go ahead. A throw, or anything but `true`, refuses with 429 (fail closed). */
export const allowedByRateLimit = async ({
  action,
  collectionSlug,
  options,
  req,
  userId,
}: {
  action: PasskeyAction
  collectionSlug: string
  options: Pick<ResolvedOptions, 'rateLimit'>
  req: PayloadRequest
  userId?: number | string
}): Promise<boolean> => {
  const ip = clientIp(req)
  const key = userId === undefined ? `ip:${ip ?? 'unknown'}` : `${collectionSlug}:${String(userId)}`
  try {
    return (await options.rateLimit({ action, collection: collectionSlug, ip, key, req, userId })) === true
  } catch (error) {
    req.payload.logger.error({ err: error, msg: 'passkeys: the rateLimit hook threw; refusing the request' })
    return false
  }
}
```

**Step 6: Add the endpoint wrapper to `src/server/http.ts`.** Every endpoint is built with it, so the guard order is the same everywhere: JSON body, Origin, session, rate limit, then the handler.

```ts
import type { Endpoint } from 'payload'

import type { PasskeyAction } from '../types.js'
import type { ResolvedOptions } from './options.js'

import { allowedByRateLimit } from './rateLimit.js'

export type HandlerArgs<A extends 'anonymous' | 'optional' | 'signed-in'> = {
  body: Record<string, unknown>
  collectionSlug: string
  options: ResolvedOptions
  req: PayloadRequest
  user: A extends 'signed-in' ? SignedInUser : null | SignedInUser
}

export const passkeyEndpoint = <A extends 'anonymous' | 'optional' | 'signed-in'>({
  action,
  auth,
  checkOrigin = true,
  collectionSlug,
  handler,
  options,
  path,
}: {
  action: PasskeyAction
  auth: A
  /** `status` alone skips it: it reports an origin mismatch instead of refusing. */
  checkOrigin?: boolean
  collectionSlug: string
  handler: (args: HandlerArgs<A>) => Promise<Response>
  options: ResolvedOptions
  path: string
}): Endpoint => ({
  handler: async (req) => {
    try {
      const body = await readJsonBody(req)
      if (checkOrigin && !originAllowed(req, options.origins)) throw new EndpointError(403, 'forbidden_origin')
      let user: null | SignedInUser = null
      if (auth === 'signed-in') user = requireSignedIn(req, collectionSlug)
      if (auth === 'optional') {
        try {
          user = requireSignedIn(req, collectionSlug)
        } catch {
          user = null
        }
      }
      const allowed = await allowedByRateLimit({ action, collectionSlug, options, req, userId: user?.id })
      if (!allowed) throw new EndpointError(429, 'rate_limited')
      return await handler({ body, collectionSlug, options, req, user } as HandlerArgs<A>)
    } catch (error) {
      if (error instanceof EndpointError) return json(req, error.status, { error: error.code })
      req.payload.logger.error({ err: error, msg: `passkeys: ${path} failed` })
      return json(req, 500, { error: 'server_error' })
    }
  },
  method: 'post',
  path,
})
```

The Origin check runs on the anonymous ceremonies as well as the signed-in ones. That is stricter than design §3 asks (browsers always send `Origin` on a `POST` fetch), and it stops another site's visitors being used to fill the anonymous-challenge cap.

**Step 7: Run the tests.** Run `pnpm test:unit test/unit/ip.spec.ts test/unit/cookies.spec.ts test/unit/http.spec.ts`. Expected: PASS.

**Step 8: Commit.**

```bash
git add src/server/http.ts src/server/cookies.ts src/server/ip.ts src/server/logging.ts src/server/rateLimit.ts src/shared/constants.ts test/unit/ip.spec.ts test/unit/cookies.spec.ts test/unit/http.spec.ts
git commit -m "feat: add request guards, browser-key cookies, privacy-aware logging and the rate-limit hook"
```

### Task 15: The challenge store (review M2, M3)

**Files:**
- Create: `src/server/challenges.ts`
- Test: `test/int/challenges.int.spec.ts`

Contract: a challenge is issued with a fresh random browser key (cookie) whose SHA-256 is stored. It is consumed **once**, by a unique insert into `passkey-challenge-uses`, before any verification. It is then deleted, whatever the outcome, and checked for type, collection, expiry, browser and (for registration) user. Expired rows are pruned on every issue. Authentication challenges are capped site-wide, and a browser has at most one outstanding.

**Step 1: Write the failing test.**

```ts
// test/int/challenges.int.spec.ts
import type { Payload, PayloadRequest } from 'payload'

import { createHash } from 'crypto'
import { createPayloadRequest, getPayload } from 'payload'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import type { ResolvedOptions } from '../../src/server/options.js'

import { ChallengeCapReached, ChallengeRejected, consumeChallenge, issueChallenge } from '../../src/server/challenges.js'
import { getPasskeysOptions } from '../../src/server/context.js'
import config from '../configs/single.js'
import { SERVER_URL } from '../helpers/api.js'

let payload: Payload
let options: ResolvedOptions

beforeAll(async () => {
  payload = await getPayload({ config })
  options = { ...getPasskeysOptions(payload), limits: { anonymousChallenges: 5, passkeysPerUser: 3 } }
})
afterAll(async () => {
  await payload.destroy()
})
beforeEach(async () => {
  await payload.db.deleteMany({ collection: 'passkey-challenges', where: {} })
  await payload.db.deleteMany({ collection: 'passkey-challenge-uses', where: {} })
})

const reqWith = (cookie?: string): Promise<PayloadRequest> =>
  createPayloadRequest({
    config,
    request: new Request(`${SERVER_URL}/api/users/passkeys/x`, {
      headers: cookie ? { Cookie: cookie.split(';')[0]! } : {},
      method: 'POST',
    }),
  })

const challenge = () => crypto.getRandomValues(new Uint8Array(32)).reduce((s, b) => s + b.toString(16).padStart(2, '0'), '').slice(0, 43)

const issue = async (type: 'authentication' | 'registration', extra: { cookie?: string; userId?: number | string } = {}) => {
  const value = challenge()
  const { setCookie } = await issueChallenge({
    challenge: value,
    collection: 'users',
    options,
    req: await reqWith(extra.cookie),
    type,
    userHandle: type === 'registration' ? 'handle' : undefined,
    userId: extra.userId,
  })
  return { cookie: setCookie, value }
}

const consume = async (value: string, cookie: string | undefined, type: 'authentication' | 'registration', userId?: number | string) =>
  consumeChallenge({ challenge: value, collection: 'users', options, req: await reqWith(cookie), type, userId })

const reason = (p: Promise<unknown>) => p.then(() => 'consumed', (e: unknown) => (e instanceof ChallengeRejected ? e.reason : String(e)))

describe('issueChallenge', () => {
  it('stores only the hash of the browser key', async () => {
    const { cookie, value } = await issue('authentication')
    const key = cookie.split(';')[0]!.split('=')[1]!
    const row = (await payload.find({ collection: 'passkey-challenges', where: { challenge: { equals: value } } })).docs[0]!
    expect(row.browserKeyHash).toBe(createHash('sha256').update(key).digest('hex'))
    expect(JSON.stringify(row)).not.toContain(key)
  })

  it('keeps one outstanding sign-in challenge per browser (review M2)', async () => {
    const first = await issue('authentication')
    await issue('authentication', { cookie: first.cookie })
    expect((await payload.count({ collection: 'passkey-challenges' })).totalDocs).toBe(1)
    expect(await reason(consume(first.value, first.cookie, 'authentication'))).toBe('unknown_challenge')
  })

  it('caps outstanding sign-in challenges site-wide (review M2)', async () => {
    for (let i = 0; i < 5; i++) await issue('authentication')
    await expect(issue('authentication')).rejects.toBeInstanceOf(ChallengeCapReached)
  })

  it('keeps one registration challenge per user', async () => {
    await issue('registration', { userId: 1 })
    await issue('registration', { userId: 1 })
    expect((await payload.count({ collection: 'passkey-challenges', where: { type: { equals: 'registration' } } })).totalDocs).toBe(1)
  })

  it('prunes expired challenges and uses', async () => {
    const past = new Date(Date.now() - 1000).toISOString()
    await payload.create({ collection: 'passkey-challenges', data: { browserKeyHash: 'x', challenge: 'old', collection: 'users', expiresAt: past, type: 'authentication' } })
    await payload.create({ collection: 'passkey-challenge-uses', data: { challenge: 'old-use', expiresAt: past } })
    await issue('authentication')
    expect((await payload.count({ collection: 'passkey-challenges', where: { challenge: { equals: 'old' } } })).totalDocs).toBe(0)
    expect((await payload.count({ collection: 'passkey-challenge-uses' })).totalDocs).toBe(0)
  })
})

describe('consumeChallenge', () => {
  it('consumes once and deletes the row', async () => {
    const { cookie, value } = await issue('authentication')
    expect((await consume(value, cookie, 'authentication')).challenge).toBe(value)
    expect((await payload.count({ collection: 'passkey-challenges' })).totalDocs).toBe(0)
    expect(await reason(consume(value, cookie, 'authentication'))).toBe('unknown_challenge')
  })

  it('refuses a replay even while the row still exists (unique insert, review M3)', async () => {
    const { cookie, value } = await issue('authentication')
    await payload.create({ collection: 'passkey-challenge-uses', data: { challenge: value, expiresAt: new Date(Date.now() + 60_000).toISOString() } })
    expect(await reason(consume(value, cookie, 'authentication'))).toBe('replayed')
  })

  it.each([
    ['wrong_type', 'authentication', 'registration'],
    ['wrong_type', 'registration', 'authentication'],
  ] as const)('refuses %s (%s consumed as %s)', async (expected, issuedAs, consumedAs) => {
    const { cookie, value } = await issue(issuedAs, { userId: 1 })
    expect(await reason(consume(value, cookie, consumedAs, 1))).toBe(expected)
  })

  it('refuses another browser and no browser (login CSRF)', async () => {
    const a = await issue('authentication')
    const b = await issue('authentication')
    expect(await reason(consume(a.value, b.cookie, 'authentication'))).toBe('wrong_browser')
    const c = await issue('authentication')
    expect(await reason(consume(c.value, undefined, 'authentication'))).toBe('wrong_browser')
  })

  it('refuses another user for registration', async () => {
    const { cookie, value } = await issue('registration', { userId: 1 })
    expect(await reason(consume(value, cookie, 'registration', 2))).toBe('wrong_user')
  })

  it('refuses an expired challenge and still deletes it', async () => {
    const { cookie, value } = await issue('authentication')
    await payload.db.updateOne({
      collection: 'passkey-challenges',
      data: { expiresAt: new Date(Date.now() - 1).toISOString() },
      returning: false,
      where: { challenge: { equals: value } },
    })
    expect(await reason(consume(value, cookie, 'authentication'))).toBe('expired')
    expect((await payload.count({ collection: 'passkey-challenges' })).totalDocs).toBe(0)
  })
})
```

Run `pnpm test:int test/int/challenges.int.spec.ts`. Expected: FAIL, module not found.

**Step 2: Write `src/server/challenges.ts`, complete.**

```ts
import type { PayloadRequest, Where } from 'payload'

import { createHash, randomBytes, timingSafeEqual } from 'crypto'

import type { CeremonyType } from './cookies.js'
import type { ResolvedOptions } from './options.js'

import { CHALLENGE_TTL_MS } from '../shared/constants.js'
import { browserKeyCookie, browserKeyCookieName, clearBrowserKeyCookie, readCookie } from './cookies.js'

export type ChallengeRecord = {
  browserKeyHash: string
  challenge: string
  collection: string
  expiresAt: string
  id: number | string
  type: CeremonyType
  userHandle?: null | string
  userId?: null | string
}

export type ChallengeRejection =
  | 'expired'
  | 'replayed'
  | 'unknown_challenge'
  | 'wrong_browser'
  | 'wrong_collection'
  | 'wrong_type'
  | 'wrong_user'

export class ChallengeRejected extends Error {
  readonly reason: ChallengeRejection
  constructor(reason: ChallengeRejection) {
    super(`Challenge rejected: ${reason}`)
    this.name = 'ChallengeRejected'
    this.reason = reason
  }
}

export class ChallengeCapReached extends Error {
  constructor() {
    super('Too many outstanding passkey sign-in challenges')
    this.name = 'ChallengeCapReached'
  }
}

const sha256Hex = (value: string): string => createHash('sha256').update(value).digest('hex')

const sameHash = (a: string, b: string): boolean => {
  const left = Buffer.from(a, 'hex')
  const right = Buffer.from(b, 'hex')
  return left.length === 32 && right.length === 32 && timingSafeEqual(left, right)
}

const prune = async (req: PayloadRequest, options: ResolvedOptions): Promise<void> => {
  const where: Where = { expiresAt: { less_than: new Date().toISOString() } }
  await req.payload.db.deleteMany({ collection: options.slugs.challenges, req, where })
  await req.payload.db.deleteMany({ collection: options.slugs.challengeUses, req, where })
}

/**
 * Stores a challenge the server generated and returns the browser-key cookie that binds it to
 * this browser. The caller sends the cookie with the options response.
 */
export const issueChallenge = async ({
  challenge,
  collection,
  options,
  req,
  type,
  userHandle,
  userId,
}: {
  challenge: string
  collection: string
  options: ResolvedOptions
  req: PayloadRequest
  type: CeremonyType
  userHandle?: string
  userId?: number | string
}): Promise<{ cookieName: string; setCookie: string }> => {
  const { payload } = req
  await prune(req, options)

  const cookieName = browserKeyCookieName(type, collection, options.secureCookies)
  if (type === 'authentication') {
    const previous = readCookie(req, cookieName)
    if (previous) {
      await payload.db.deleteMany({
        collection: options.slugs.challenges,
        req,
        where: {
          and: [
            { type: { equals: 'authentication' } },
            { browserKeyHash: { equals: sha256Hex(previous) } },
          ],
        },
      })
    }
    const { totalDocs } = await payload.db.count({
      collection: options.slugs.challenges,
      req,
      where: { type: { equals: 'authentication' } },
    })
    if (totalDocs >= options.limits.anonymousChallenges) throw new ChallengeCapReached()
  } else {
    if (userId === undefined) throw new Error('A registration challenge needs a user')
    await payload.db.deleteMany({
      collection: options.slugs.challenges,
      req,
      where: {
        and: [
          { type: { equals: 'registration' } },
          { collection: { equals: collection } },
          { userId: { equals: String(userId) } },
        ],
      },
    })
  }

  const browserKey = randomBytes(32).toString('base64url')
  await payload.create({
    collection: options.slugs.challenges as never,
    data: {
      browserKeyHash: sha256Hex(browserKey),
      challenge,
      collection,
      expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS).toISOString(),
      type,
      ...(userHandle ? { userHandle } : {}),
      ...(userId !== undefined ? { userId: String(userId) } : {}),
    } as never,
    overrideAccess: true,
    req,
  })
  return { cookieName, setCookie: browserKeyCookie(cookieName, browserKey, options.secureCookies) }
}

/** The cookie line that clears this ceremony's browser key. Send it with every verify response. */
export const clearChallengeCookie = (options: ResolvedOptions, type: CeremonyType, collection: string): string =>
  clearBrowserKeyCookie(browserKeyCookieName(type, collection, options.secureCookies), options.secureCookies)

/**
 * Single use, before any verification. The unique insert is the lock: of two parallel requests
 * with the same challenge, exactly one insert succeeds on every adapter (review M3). The row is
 * deleted whatever happens next, then checked.
 */
export const consumeChallenge = async ({
  challenge,
  collection,
  options,
  req,
  type,
  userId,
}: {
  challenge: string
  collection: string
  options: ResolvedOptions
  req: PayloadRequest
  type: CeremonyType
  userId?: number | string
}): Promise<ChallengeRecord> => {
  const { payload } = req
  const found = await payload.find({
    collection: options.slugs.challenges as never,
    depth: 0,
    limit: 1,
    overrideAccess: true,
    pagination: false,
    req,
    where: { challenge: { equals: challenge } },
  })
  const record = found.docs[0] as ChallengeRecord | undefined
  if (!record) throw new ChallengeRejected('unknown_challenge')

  try {
    await payload.create({
      collection: options.slugs.challengeUses as never,
      data: { challenge, expiresAt: record.expiresAt } as never,
      overrideAccess: true,
      req,
    })
  } catch {
    throw new ChallengeRejected('replayed')
  }
  await payload.db.deleteMany({ collection: options.slugs.challenges, req, where: { id: { equals: record.id } } })

  if (record.type !== type) throw new ChallengeRejected('wrong_type')
  if (record.collection !== collection) throw new ChallengeRejected('wrong_collection')
  if (!(Date.parse(record.expiresAt) > Date.now())) throw new ChallengeRejected('expired')
  const key = readCookie(req, browserKeyCookieName(type, collection, options.secureCookies))
  if (!key || !sameHash(sha256Hex(key), record.browserKeyHash)) throw new ChallengeRejected('wrong_browser')
  if (type === 'registration' && record.userId !== String(userId)) throw new ChallengeRejected('wrong_user')
  return record
}
```

Notes for the implementer:
- `payload.create` is used for both inserts so that Payload's own unique validation and the database constraint both apply. `db.deleteMany` and `db.count` skip hooks on purpose (these collections have none).
- The cap is a count, then a create, so it is approximate under concurrency. That is fine: it bounds storage, and the `rateLimit` hook bounds the rate.
- Nothing here runs inside `req.transactionID`, so the use row commits before verification starts. Don't move a consume into `mintSession`'s transaction.

**Step 3: Run the tests.** Run `pnpm test:int test/int/challenges.int.spec.ts` on all three adapters. Expected: PASS.

**Step 4: Commit.**

```bash
git add src/server/challenges.ts test/int/challenges.int.spec.ts
git commit -m "feat: add the single-use, browser-bound challenge store"
```

### Task 16: Counter policy, dummy verification and response parsing (review M7, L6)

**Files:**
- Create: `src/server/counterPolicy.ts`, `src/server/dummyCredential.ts`, `src/server/webauthnJson.ts`
- Test: `test/unit/counterPolicy.spec.ts`, `test/unit/webauthnJson.spec.ts`

**Step 1: Write the failing tests.**

```ts
// test/unit/counterPolicy.spec.ts
import { describe, expect, it } from 'vitest'

import { decideCounter } from '../../src/server/counterPolicy.js'

const stored = (counter: number, deviceType: 'multiDevice' | 'singleDevice', backedUp = deviceType === 'multiDevice') => ({ backedUp, counter, deviceType })
const reported = (newCounter: number, deviceType: 'multiDevice' | 'singleDevice', backedUp = deviceType === 'multiDevice') => ({ backedUp, deviceType, newCounter })

describe('decideCounter (review M7)', () => {
  it('accepts zero counters (synced passkeys report 0)', () => {
    expect(decideCounter(stored(0, 'multiDevice'), reported(0, 'multiDevice'))).toEqual({ action: 'accept', backedUp: true, counter: 0, regression: false })
  })
  it('accepts an increase and stores it', () => {
    expect(decideCounter(stored(5, 'singleDevice'), reported(6, 'singleDevice'))).toMatchObject({ action: 'accept', counter: 6, regression: false })
  })
  it('refuses a device-bound passkey whose counter did not increase', () => {
    expect(decideCounter(stored(5, 'singleDevice'), reported(5, 'singleDevice'))).toEqual({ action: 'refuse', reason: 'counter_not_increased' })
    expect(decideCounter(stored(5, 'singleDevice'), reported(0, 'singleDevice'))).toEqual({ action: 'refuse', reason: 'counter_not_increased' })
  })
  it('lets a synced passkey through a regression but never lowers the stored counter', () => {
    expect(decideCounter(stored(9, 'multiDevice'), reported(3, 'multiDevice'))).toEqual({ action: 'accept', backedUp: true, counter: 9, regression: true })
  })
  it('refuses a change of device type (BE must never change)', () => {
    expect(decideCounter(stored(0, 'multiDevice'), reported(0, 'singleDevice'))).toEqual({ action: 'refuse', reason: 'device_type_changed' })
    expect(decideCounter(stored(0, 'singleDevice'), reported(1, 'multiDevice'))).toEqual({ action: 'refuse', reason: 'device_type_changed' })
  })
  it('follows the backup state', () => {
    expect(decideCounter(stored(0, 'multiDevice', false), reported(0, 'multiDevice', true))).toMatchObject({ backedUp: true })
    expect(decideCounter(stored(0, 'multiDevice', true), reported(0, 'multiDevice', false))).toMatchObject({ backedUp: false })
  })
})
```

```ts
// test/unit/webauthnJson.spec.ts
import { describe, expect, it } from 'vitest'

import { challengeFromClientData, parseAuthenticationResponse, parseRegistrationResponse } from '../../src/server/webauthnJson.js'

const b64 = (value: string) => Buffer.from(value).toString('base64url')
const challenge = 'A'.repeat(43)

describe('challengeFromClientData', () => {
  it('reads a 43-character base64url challenge', () => {
    expect(challengeFromClientData(b64(JSON.stringify({ challenge, type: 'webauthn.get' })))).toBe(challenge)
  })
  it.each([b64('{'), b64(JSON.stringify({ challenge: 'short' })), b64(JSON.stringify({ challenge: 'A'.repeat(42) + '=' })), '***', 42])(
    'returns null for %j',
    (value) => {
      expect(challengeFromClientData(value)).toBeNull()
    },
  )
})

describe('parse responses', () => {
  const auth = {
    authenticatorAttachment: 'platform',
    clientExtensionResults: {},
    id: 'abc',
    rawId: 'abc',
    response: { authenticatorData: 'AA', clientDataJSON: 'AA', signature: 'AA', userHandle: 'AA' },
    type: 'public-key',
    extra: 'dropped',
  }
  it('keeps only known keys', () => {
    expect(parseAuthenticationResponse(auth)).not.toHaveProperty('extra')
  })
  it.each([
    { ...auth, type: 'password' },
    { ...auth, rawId: 'other' },
    { ...auth, id: 'a+b' },
    { ...auth, id: 'A'.repeat(1400), rawId: 'A'.repeat(1400) },
    { ...auth, response: { ...auth.response, signature: 7 } },
    null,
    [],
  ])('refuses a malformed assertion (%#)', (value) => {
    expect(parseAuthenticationResponse(value)).toBeNull()
  })
  it('refuses a malformed attestation', () => {
    expect(parseRegistrationResponse({ ...auth, response: { clientDataJSON: 'AA' } })).toBeNull()
    expect(
      parseRegistrationResponse({ ...auth, response: { attestationObject: 'AA', clientDataJSON: 'AA', transports: ['internal', 7] } }),
    ).toBeNull()
  })
})
```

Run `pnpm test:unit test/unit/counterPolicy.spec.ts test/unit/webauthnJson.spec.ts`. Expected: FAIL, modules not found.

**Step 2: Write `src/server/counterPolicy.ts`, complete.**

```ts
import type { DeviceType } from '../types.js'

export type CounterDecision =
  | { action: 'accept'; backedUp: boolean; counter: number; regression: boolean }
  | { action: 'refuse'; reason: 'counter_not_increased' | 'device_type_changed' }

/**
 * SimpleWebAuthn is always given counter 0 (it throws on any non-increase otherwise), and this
 * decides instead (review M7):
 * - BE (device type) must never change;
 * - a device-bound passkey must increase its counter unless both values are 0;
 * - a synced passkey may regress (several devices share it): log it, keep the higher value;
 * - the stored counter never goes down; backedUp follows BS.
 */
export const decideCounter = (
  stored: { backedUp: boolean; counter: number; deviceType: DeviceType },
  reported: { backedUp: boolean; deviceType: DeviceType; newCounter: number },
): CounterDecision => {
  if (reported.deviceType !== stored.deviceType) return { action: 'refuse', reason: 'device_type_changed' }
  const bothZero = stored.counter === 0 && reported.newCounter === 0
  const increased = reported.newCounter > stored.counter
  if (!increased && !bothZero) {
    if (stored.deviceType === 'singleDevice') return { action: 'refuse', reason: 'counter_not_increased' }
    return { action: 'accept', backedUp: reported.backedUp, counter: stored.counter, regression: true }
  }
  return { action: 'accept', backedUp: reported.backedUp, counter: Math.max(stored.counter, reported.newCounter), regression: false }
}
```

**Step 3: Write `src/server/webauthnJson.ts`, complete.**

```ts
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server'

const B64URL = /^[A-Za-z0-9_-]+$/
/** Credential IDs are at most 1023 bytes (WebAuthn L3), 1364 base64url characters. */
const MAX_ID = 1364
const MAX_FIELD = 32 * 1024

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v)
const b64 = (v: unknown, max = MAX_FIELD): v is string => typeof v === 'string' && v.length <= max && B64URL.test(v)

/** The challenge a client signed, read from clientDataJSON, or null. Verified again by the library. */
export const challengeFromClientData = (clientDataJSON: unknown): null | string => {
  if (!b64(clientDataJSON)) return null
  try {
    const parsed: unknown = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'))
    const challenge = isObj(parsed) ? parsed.challenge : undefined
    return typeof challenge === 'string' && /^[A-Za-z0-9_-]{43}$/.test(challenge) ? challenge : null
  } catch {
    return null
  }
}

const base = (value: unknown): null | { attachment?: string; ext: Obj; id: string; response: Obj } => {
  if (!isObj(value) || value.type !== 'public-key') return null
  if (!b64(value.id, MAX_ID) || value.rawId !== value.id || !isObj(value.response)) return null
  const ext = value.clientExtensionResults === undefined ? {} : value.clientExtensionResults
  if (!isObj(ext)) return null
  const attachment = value.authenticatorAttachment
  if (attachment !== undefined && attachment !== 'platform' && attachment !== 'cross-platform') return null
  return { attachment: attachment as string | undefined, ext, id: value.id, response: value.response }
}

export const parseRegistrationResponse = (value: unknown): null | RegistrationResponseJSON => {
  const parsed = base(value)
  if (!parsed) return null
  const { attestationObject, clientDataJSON, transports } = parsed.response
  if (!b64(attestationObject) || !b64(clientDataJSON)) return null
  if (transports !== undefined && !(Array.isArray(transports) && transports.length <= 10 && transports.every((t) => typeof t === 'string' && t.length <= 32))) {
    return null
  }
  return {
    authenticatorAttachment: parsed.attachment as RegistrationResponseJSON['authenticatorAttachment'],
    clientExtensionResults: parsed.ext as RegistrationResponseJSON['clientExtensionResults'],
    id: parsed.id,
    rawId: parsed.id,
    response: {
      attestationObject,
      clientDataJSON,
      ...(transports ? { transports: transports as RegistrationResponseJSON['response']['transports'] } : {}),
    },
    type: 'public-key',
  }
}

export const parseAuthenticationResponse = (value: unknown): AuthenticationResponseJSON | null => {
  const parsed = base(value)
  if (!parsed) return null
  const { authenticatorData, clientDataJSON, signature, userHandle } = parsed.response
  if (!b64(authenticatorData) || !b64(clientDataJSON) || !b64(signature)) return null
  if (userHandle !== undefined && !b64(userHandle, 128)) return null
  return {
    authenticatorAttachment: parsed.attachment as AuthenticationResponseJSON['authenticatorAttachment'],
    clientExtensionResults: parsed.ext as AuthenticationResponseJSON['clientExtensionResults'],
    id: parsed.id,
    rawId: parsed.id,
    response: { authenticatorData, clientDataJSON, signature, ...(userHandle ? { userHandle } : {}) },
    type: 'public-key',
  }
}
```

**Step 4: Write `src/server/dummyCredential.ts`, complete.**

```ts
import { verifyAuthenticationResponse } from '@simplewebauthn/server'
import { isoCBOR } from '@simplewebauthn/server/helpers'

import type { AuthenticationResponseJSON } from '@simplewebauthn/server'

import type { ResolvedOptions } from './options.js'

let dummyKey: Promise<Uint8Array> | undefined

/** A COSE ES256 public key made once per process. Nothing can sign for it. */
const dummyPublicKey = (): Promise<Uint8Array> =>
  (dummyKey ??= (async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
    return isoCBOR.encode(
      new Map<number, number | Uint8Array>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, raw.slice(1, 33)],
        [-3, raw.slice(33, 65)],
      ]),
    )
  })())

/**
 * Runs the same verification as a known credential against a key nobody holds, so an unknown
 * credential takes about as long to refuse as a known one (review L6). Always resolves.
 */
export const verifyAgainstDummy = async (
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
  options: Pick<ResolvedOptions, 'origins' | 'rpID'>,
): Promise<void> => {
  try {
    await verifyAuthenticationResponse({
      credential: { counter: 0, id: response.id, publicKey: await dummyPublicKey() as Uint8Array<ArrayBuffer> },
      expectedChallenge,
      expectedOrigin: options.origins,
      expectedRPID: options.rpID,
      requireUserVerification: true,
      response,
    })
  } catch {
    // Expected: the signature can't verify.
  }
}
```

`Uint8Array_` in SimpleWebAuthn 14 is `Uint8Array<ArrayBuffer>`; the cast matches it. If `tsc` reports a different generic on the installed TypeScript, use the library's exported `Uint8Array_` type for the cast.

**Step 5: Run the tests.** Run `pnpm test:unit test/unit/counterPolicy.spec.ts test/unit/webauthnJson.spec.ts`. Expected: PASS.

**Step 6: Commit.**

```bash
git add src/server/counterPolicy.ts src/server/dummyCredential.ts src/server/webauthnJson.ts test/unit/counterPolicy.spec.ts test/unit/webauthnJson.spec.ts
git commit -m "feat: add the counter policy, dummy verification and strict response parsing"
```

### Task 17: The soft authenticator (test helper)

**Files:**
- Create: `test/helpers/softAuthenticator.ts`
- Test: `test/unit/softAuthenticator.spec.ts`

**Step 1: Write the failing test.** It proves the helper against SimpleWebAuthn directly, with no Payload, so a later integration failure is never the helper's fault.

```ts
// test/unit/softAuthenticator.spec.ts
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server'
import { isoBase64URL } from '@simplewebauthn/server/helpers'
import { describe, expect, it } from 'vitest'

import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'

const origin = 'http://localhost:3000'
const rpID = 'localhost'

const setUp = async (options: Parameters<typeof createSoftAuthenticator>[0] = { origin }) => {
  const authenticator = createSoftAuthenticator(options)
  const regOptions = await generateRegistrationOptions({
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    rpID,
    rpName: 'Test',
    userID: isoBase64URL.toBuffer('dXNlci1oYW5kbGU'),
    userName: 'a@example.test',
  })
  const registration = await verifyRegistrationResponse({
    expectedChallenge: regOptions.challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    requireUserVerification: true,
    response: await authenticator.register(regOptions),
  })
  if (!registration.verified) throw new Error('registration failed')
  const credential = registration.registrationInfo.credential
  const assert = async (overrides: Parameters<typeof authenticator.authenticate>[1] = {}) => {
    const authOptions = await generateAuthenticationOptions({ rpID, userVerification: 'required' })
    const response = await authenticator.authenticate(authOptions, overrides)
    return { response, result: await verifyAuthenticationResponse({ credential: { ...credential, counter: 0 }, expectedChallenge: authOptions.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true, response }) }
  }
  return { assert, authenticator, registration }
}

describe('soft authenticator', () => {
  it('registers a synced passkey by default', async () => {
    const { registration } = await setUp({ aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4', origin })
    expect(registration.registrationInfo).toMatchObject({ aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4', credentialBackedUp: true, credentialDeviceType: 'multiDevice' })
  })

  it('registers a device-bound passkey with BE=0', async () => {
    const { registration } = await setUp({ backupEligible: false, origin })
    expect(registration.registrationInfo).toMatchObject({ credentialBackedUp: false, credentialDeviceType: 'singleDevice' })
  })

  it('asserts, and the user handle round-trips', async () => {
    const { assert } = await setUp()
    const { response, result } = await assert()
    expect(result.verified).toBe(true)
    expect(response.response.userHandle).toBe('dXNlci1oYW5kbGU')
  })

  it('reports the real counter when the library is given 0', async () => {
    const { assert } = await setUp({ incrementCounter: true, origin })
    await assert()
    expect((await assert()).result.authenticationInfo.newCounter).toBe(2)
  })

  it.each([
    [{ userVerified: false }, /User verification/],
    [{ origin: 'https://evil.test' }, /origin/],
    [{ rpID: 'evil.test' }, /RP ID/],
    [{ type: 'webauthn.create' }, /type/],
  ])('fails with %j', async (overrides, message) => {
    const { assert } = await setUp()
    await expect(assert(overrides)).rejects.toThrow(message)
  })

  it('produces an unverifiable signature on request', async () => {
    const { assert } = await setUp()
    expect((await assert({ badSignature: true })).result.verified).toBe(false)
  })
})
```

Run `pnpm test:unit test/unit/softAuthenticator.spec.ts`. Expected: FAIL, module not found.

**Step 2: Write `test/helpers/softAuthenticator.ts`, complete.** This is the version verified in a scratch project on 2026-11-06 (Verified facts Q6).

```ts
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server'

import { isoBase64URL, isoCBOR } from '@simplewebauthn/server/helpers'

const FLAG_UP = 0x01
const FLAG_UV = 0x04
const FLAG_BE = 0x08
const FLAG_BS = 0x10
const FLAG_AT = 0x40

export type CeremonyOverrides = {
  /** Sign with a different key than the stored one (bad signature). */
  badSignature?: boolean
  backupEligible?: boolean
  backupState?: boolean
  /** Replace the challenge in clientDataJSON. */
  challenge?: string
  /** Set the counter explicitly for this ceremony instead of incrementing. */
  counter?: number
  /** credProps.rk reported to the server (registration only). null omits credProps. */
  credPropsRk?: boolean | null
  origin?: string
  rpID?: string
  type?: string
  userHandle?: null | string
  userPresent?: boolean
  userVerified?: boolean
}

type StoredCredential = {
  backupEligible: boolean
  backupState: boolean
  counter: number
  id: Uint8Array
  privateKey: CryptoKey
  publicKey: CryptoKey
  rpID: string
  userHandle: string
}

export type SoftAuthenticatorOptions = {
  aaguid?: string
  backupEligible?: boolean
  backupState?: boolean
  /** Counters stay 0 (like a synced passkey) unless this is set. */
  incrementCounter?: boolean
  origin: string
}

const enc = new TextEncoder()

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

const u32 = (n: number): Uint8Array => {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, false)
  return b
}

const u16 = (n: number): Uint8Array => {
  const b = new Uint8Array(2)
  new DataView(b.buffer).setUint16(0, n, false)
  return b
}

const sha256 = async (data: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', data))

const aaguidBytes = (aaguid: string): Uint8Array => {
  const hex = aaguid.replace(/-/g, '')
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new Error(`Bad AAGUID ${aaguid}`)
  return Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)))
}

/** DER-encode a raw (r || s) P-256 signature, which is what WebAuthn ES256 requires. */
const rawToDer = (raw: Uint8Array): Uint8Array => {
  const int = (bytes: Uint8Array): Uint8Array => {
    let i = 0
    while (i < bytes.length - 1 && bytes[i] === 0) i++
    let v = bytes.slice(i)
    if (v[0]! & 0x80) v = concat(new Uint8Array([0]), v)
    return concat(new Uint8Array([0x02, v.length]), v)
  }
  const body = concat(int(raw.slice(0, 32)), int(raw.slice(32)))
  return concat(new Uint8Array([0x30, body.length]), body)
}

const coseES256 = async (publicKey: CryptoKey): Promise<Uint8Array> => {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey)) // 0x04 || x || y
  return isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, raw.slice(1, 33)], // x
      [-3, raw.slice(33, 65)], // y
    ]),
  )
}

const flagsByte = (o: { at?: boolean; be: boolean; bs: boolean; up: boolean; uv: boolean }): number =>
  (o.up ? FLAG_UP : 0) | (o.uv ? FLAG_UV : 0) | (o.be ? FLAG_BE : 0) | (o.bs ? FLAG_BS : 0) | (o.at ? FLAG_AT : 0)

const clientData = (type: string, challenge: string, origin: string): Uint8Array =>
  enc.encode(JSON.stringify({ type, challenge, origin, crossOrigin: false }))

/**
 * A software WebAuthn authenticator for integration tests: ES256 keys from WebCrypto,
 * attestation "none", and full control over every flag the server must check.
 */
export const createSoftAuthenticator = (options: SoftAuthenticatorOptions) => {
  const aaguid = options.aaguid ?? '00000000-0000-0000-0000-000000000000'
  const credentials = new Map<string, StoredCredential>()

  const register = async (
    optionsJSON: PublicKeyCredentialCreationOptionsJSON,
    o: CeremonyOverrides = {},
  ): Promise<RegistrationResponseJSON> => {
    const keyPair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const id = crypto.getRandomValues(new Uint8Array(32))
    const rpID = o.rpID ?? optionsJSON.rp.id ?? new URL(options.origin).hostname
    const be = o.backupEligible ?? options.backupEligible ?? true
    const bs = o.backupState ?? options.backupState ?? be
    const counter = o.counter ?? 0

    const authData = concat(
      await sha256(enc.encode(rpID)),
      new Uint8Array([flagsByte({ at: true, be, bs, up: o.userPresent ?? true, uv: o.userVerified ?? true })]),
      u32(counter),
      aaguidBytes(aaguid),
      u16(id.length),
      id,
      await coseES256(keyPair.publicKey),
    )
    const attestationObject = isoCBOR.encode(
      new Map<string, Map<string, never> | number | string | Uint8Array>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', authData],
      ]),
    )
    const cdj = clientData(o.type ?? 'webauthn.create', o.challenge ?? optionsJSON.challenge, o.origin ?? options.origin)
    const credentialId = isoBase64URL.fromBuffer(id)
    credentials.set(credentialId, {
      backupEligible: be,
      backupState: bs,
      counter,
      id,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      rpID,
      userHandle: optionsJSON.user.id,
    })

    const rk = o.credPropsRk === undefined ? true : o.credPropsRk
    return {
      authenticatorAttachment: 'platform',
      clientExtensionResults: rk === null ? {} : { credProps: { rk } },
      id: credentialId,
      rawId: credentialId,
      response: {
        attestationObject: isoBase64URL.fromBuffer(attestationObject),
        authenticatorData: isoBase64URL.fromBuffer(authData),
        clientDataJSON: isoBase64URL.fromBuffer(cdj),
        publicKeyAlgorithm: -7,
        transports: ['internal', 'hybrid'],
      },
      type: 'public-key',
    }
  }

  const authenticate = async (
    optionsJSON: PublicKeyCredentialRequestOptionsJSON,
    o: CeremonyOverrides & { credentialId?: string } = {},
  ): Promise<AuthenticationResponseJSON> => {
    const credentialId = o.credentialId ?? [...credentials.keys()].at(-1)
    const cred = credentialId ? credentials.get(credentialId) : undefined
    if (!credentialId || !cred) throw new Error('Soft authenticator has no such credential')

    if (o.counter !== undefined) cred.counter = o.counter
    else if (options.incrementCounter) cred.counter += 1

    const rpID = o.rpID ?? optionsJSON.rpId ?? cred.rpID
    const be = o.backupEligible ?? cred.backupEligible
    const bs = o.backupState ?? cred.backupState
    const authData = concat(
      await sha256(enc.encode(rpID)),
      new Uint8Array([flagsByte({ be, bs, up: o.userPresent ?? true, uv: o.userVerified ?? true })]),
      u32(cred.counter),
    )
    const cdj = clientData(o.type ?? 'webauthn.get', o.challenge ?? optionsJSON.challenge, o.origin ?? options.origin)
    const signingKey = o.badSignature
      ? ((await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])) as CryptoKeyPair)
          .privateKey
      : cred.privateKey
    const signed = concat(authData, await sha256(cdj))
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKey, signed))
    const userHandle = o.userHandle === undefined ? cred.userHandle : o.userHandle

    return {
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      id: credentialId,
      rawId: credentialId,
      response: {
        authenticatorData: isoBase64URL.fromBuffer(authData),
        clientDataJSON: isoBase64URL.fromBuffer(cdj),
        signature: isoBase64URL.fromBuffer(rawToDer(raw)),
        ...(userHandle === null ? {} : { userHandle }),
      },
      type: 'public-key',
    }
  }

  return {
    authenticate,
    credentialIds: () => [...credentials.keys()],
    forget: (credentialId: string) => credentials.delete(credentialId),
    register,
  }
}

export type SoftAuthenticator = ReturnType<typeof createSoftAuthenticator>
```

**Step 3: Run the test.** Run `pnpm test:unit test/unit/softAuthenticator.spec.ts`. Expected: PASS (9 tests).

**Step 4: Commit.**

```bash
git add test/helpers/softAuthenticator.ts test/unit/softAuthenticator.spec.ts
git commit -m "test: add a WebCrypto soft authenticator with per-ceremony overrides"
```

### Task 18: Passkey records, user details, `register/options` and `reauth` (review H1, L4)

**Files:**
- Create: `src/server/passkeyRecords.ts`, `src/server/userInfo.ts`, `src/server/endpoints/registerOptions.ts`, `src/server/endpoints/reauth.ts`, `test/helpers/ceremonies.ts`
- Modify: `src/server/endpoints/index.ts`
- Test: `test/int/registerOptions.int.spec.ts`

**Step 1: Write the ceremony helpers.**

```ts
// test/helpers/ceremonies.ts
import type { Payload, SanitizedConfig } from 'payload'

import type { TestClient } from './api.js'
import type { CeremonyOverrides, SoftAuthenticator } from './softAuthenticator.js'

import { createClient } from './api.js'
import { PASSWORD, rawUser } from './users.js'

type Config = Promise<SanitizedConfig>

export const passwordClient = async (config: Config, collection: string, email: string): Promise<TestClient> => {
  const client = createClient(config)
  const res = await client.post(`/api/${collection}/login`, { email, password: PASSWORD })
  if (res.status !== 200) throw new Error(`login failed: ${res.status} ${JSON.stringify(res.json)}`)
  return client
}

/** Moves a user's newest session's createdAt into the past, to make it stale. */
export const ageNewestSession = async (payload: Payload, collection: string, userId: number | string, minutes: number) => {
  const { sessions = [] } = await rawUser(payload, collection, userId)
  const newest = sessions.at(-1)!
  newest.createdAt = new Date(Date.now() - minutes * 60_000).toISOString()
  await payload.db.updateOne({ collection, data: { sessions }, id: userId, returning: false })
}

export const registerPasskey = async (
  client: TestClient,
  authenticator: SoftAuthenticator,
  { collection = 'users', name, overrides }: { collection?: string; name?: string; overrides?: CeremonyOverrides } = {},
) => {
  const options = await client.post(`/api/${collection}/passkeys/register/options`)
  if (options.status !== 200) return { options, verify: null }
  const response = await authenticator.register(options.json.options, overrides)
  const verify = await client.post(`/api/${collection}/passkeys/register/verify`, { name, response })
  return { options, response, verify }
}

export const signInWithPasskey = async (
  client: TestClient,
  authenticator: SoftAuthenticator,
  { collection = 'users', overrides }: { collection?: string; overrides?: CeremonyOverrides & { credentialId?: string } } = {},
) => {
  const options = await client.post(`/api/${collection}/passkeys/sign-in/options`)
  if (options.status !== 200) return { options, response: null, verify: null }
  const response = await authenticator.authenticate(options.json.options, overrides)
  const verify = await client.post(`/api/${collection}/passkeys/sign-in/verify`, { response })
  return { options, response, verify }
}
```

**Step 2: Write the failing test.**

```ts
// test/int/registerOptions.int.spec.ts
import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import config from '../configs/single.js'
import { createClient } from '../helpers/api.js'
import { ageNewestSession, passwordClient } from '../helpers/ceremonies.js'
import { insertPasskey } from '../helpers/passkeys.js'
import { createUser, PASSWORD, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const OPTIONS = '/api/users/passkeys/register/options'

describe('register/options', () => {
  it('needs a cookie session of this collection', async () => {
    expect((await createClient(config).post(OPTIONS)).json).toEqual({ error: 'unauthorised' })
    const apiKey = crypto.randomUUID()
    await createUser(payload, 'users', { apiKey, enableAPIKey: true })
    const res = await createClient(config).post(OPTIONS, {}, { headers: { Authorization: `users API-Key ${apiKey}` } })
    expect(res.status).toBe(403)
  })

  it('returns discoverable, UV-required creation options bound to this browser', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    const res = await client.post(OPTIONS)
    expect(res.status).toBe(200)
    const handle = (await rawUser(payload, 'users', user.id)).passkeyUserHandle
    expect(handle).toMatch(/^[A-Za-z0-9_-]{86}$/)
    expect(res.json.options).toMatchObject({
      attestation: 'none',
      authenticatorSelection: { requireResidentKey: true, residentKey: 'required', userVerification: 'required' },
      extensions: { credProps: true },
      rp: { id: 'localhost' },
      timeout: 300_000,
      user: { displayName: 'Test User', id: handle, name: user.email },
    })
    expect(res.json.options.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(res.json.options.pubKeyCredParams.map((p: { alg: number }) => p.alg)).toEqual([-8, -7, -257])
    expect(client.cookies.has('payload-passkeys-reg-users')).toBe(true)
  })

  it('keeps the same user handle across calls', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    const a = await client.post(OPTIONS)
    const b = await client.post(OPTIONS)
    expect(a.json.options.user.id).toBe(b.json.options.user.id)
  })

  it('lists existing passkeys in excludeCredentials', async () => {
    const user = await createUser(payload, 'users')
    const row = await insertPasskey(payload, { collection: 'users', userId: user.id })
    const res = await (await passwordClient(config, 'users', user.email)).post(OPTIONS)
    expect(res.json.options.excludeCredentials.map((c: { id: string }) => c.id)).toEqual([row.credentialId])
  })

  it('asks for the password when the session is older than freshSessionMinutes', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    await ageNewestSession(payload, 'users', user.id, 11)
    const res = await client.post(OPTIONS)
    expect(res.status).toBe(403)
    expect(res.json).toEqual({ error: 'reauth_required' })
  })

  it('stops at the per-user cap', async () => {
    const user = await createUser(payload, 'users')
    for (let i = 0; i < 3; i++) await insertPasskey(payload, { collection: 'users', userId: user.id })
    const res = await (await passwordClient(config, 'users', user.email)).post(OPTIONS)
    expect(res.status).toBe(409)
    expect(res.json).toEqual({ error: 'too_many_passkeys' })
  })
})

describe('reauth (review H1)', () => {
  it('refuses a wrong password and counts it', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    const res = await client.post('/api/users/passkeys/reauth', { password: 'wrong' })
    expect(res.status).toBe(401)
    expect(res.json).toEqual({ error: 'reauth_failed' })
    expect((await rawUser(payload, 'users', user.id)).loginAttempts).toBe(1)
  })

  it('moves the browser to a fresh session so register/options works again', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    await ageNewestSession(payload, 'users', user.id, 30)
    const before = (await rawUser(payload, 'users', user.id)).sessions!.map((s) => s.id)
    const res = await client.post('/api/users/passkeys/reauth', { password: PASSWORD })
    expect(res.status).toBe(200)
    expect(res.json.user.id).toBe(user.id)
    const after = (await rawUser(payload, 'users', user.id)).sessions!.map((s) => s.id)
    expect(after.some((id) => before.includes(id))).toBe(false)
    expect((await client.post(OPTIONS)).status).toBe(200)
  })

  it('takes the identifier from the session, never the body', async () => {
    const victim = await createUser(payload, 'users')
    const attacker = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', attacker.email)
    await client.post('/api/users/passkeys/reauth', { email: victim.email, password: 'guess' })
    expect((await rawUser(payload, 'users', victim.id)).loginAttempts ?? 0).toBe(0)
  })
})
```

Run `pnpm test:int test/int/registerOptions.int.spec.ts`. Expected: FAIL (404s: no endpoints yet).

**Step 3: Write `src/server/passkeyRecords.ts`, complete.**

```ts
import type { PayloadRequest } from 'payload'

import type { DeviceType, PublicPasskey } from '../types.js'
import type { ResolvedOptions } from './options.js'

import { ownPasskeysWhere } from '../collections/passkeys.js'

type Ref = number | string | { id: number | string }

export type PasskeyRow = {
  aaguid?: null | string
  backedUp: boolean
  collection: string
  counter: number
  createdAt: string
  credentialId: string
  deviceType: DeviceType
  id: number | string
  lastUsedAt?: null | string
  name: string
  publicKey: string
  rpID: string
  transports?: null | string[]
  user: { relationTo: string; value: Ref } | Ref
  userHandle: string
}

const idOf = (ref: Ref | null | undefined): null | number | string =>
  ref === null || ref === undefined ? null : typeof ref === 'object' ? ref.id : ref

/** The row's owner. Null when the relationship and the collection column disagree (H3). */
export const ownerOf = (row: PasskeyRow): null | { collection: string; id: number | string } => {
  const { user } = row
  if (user && typeof user === 'object' && 'relationTo' in user) {
    if (user.relationTo !== row.collection) return null
    const id = idOf(user.value)
    return id === null ? null : { collection: row.collection, id }
  }
  const id = idOf(user as Ref)
  return id === null ? null : { collection: row.collection, id }
}

export const toPublicPasskey = (row: PasskeyRow): PublicPasskey => ({
  aaguid: row.aaguid ?? null,
  backedUp: Boolean(row.backedUp),
  createdAt: row.createdAt,
  credentialId: row.credentialId,
  deviceType: row.deviceType,
  id: row.id,
  lastUsedAt: row.lastUsedAt ?? null,
  name: row.name,
  rpID: row.rpID,
  transports: Array.isArray(row.transports) ? row.transports : [],
})

/** Every field, including key material. Server use only. */
export const findPasskeyByCredentialId = async (
  req: PayloadRequest,
  options: ResolvedOptions,
  credentialId: string,
): Promise<null | PasskeyRow> => {
  const { docs } = await req.payload.find({
    collection: options.slugs.passkeys as never,
    depth: 0,
    limit: 1,
    overrideAccess: true,
    pagination: false,
    req,
    where: { credentialId: { equals: credentialId } },
  })
  return (docs[0] as PasskeyRow | undefined) ?? null
}

export const listPasskeysOfUser = async (
  req: PayloadRequest,
  options: ResolvedOptions,
  collection: string,
  userId: number | string,
): Promise<PasskeyRow[]> => {
  const { docs } = await req.payload.find({
    collection: options.slugs.passkeys as never,
    depth: 0,
    limit: 0,
    overrideAccess: true,
    pagination: false,
    req,
    sort: '-createdAt',
    where: ownPasskeysWhere(options, collection, userId),
  })
  return docs as PasskeyRow[]
}

/** One of this user's passkeys by row ID, or null. Collection and ID are both matched (H3). */
export const findOwnPasskey = async (
  req: PayloadRequest,
  options: ResolvedOptions,
  collection: string,
  userId: number | string,
  id: unknown,
): Promise<null | PasskeyRow> => {
  if ((typeof id !== 'string' && typeof id !== 'number') || String(id).length > 64) return null
  const { docs } = await req.payload.find({
    collection: options.slugs.passkeys as never,
    depth: 0,
    limit: 1,
    overrideAccess: true,
    pagination: false,
    req,
    where: { and: [{ id: { equals: id } }, ownPasskeysWhere(options, collection, userId)] },
  })
  return (docs[0] as PasskeyRow | undefined) ?? null
}
```

**Step 4: Write `src/server/userInfo.ts`, complete.**

```ts
import type { PayloadRequest, SanitizedCollectionConfig } from 'payload'

import { randomBytes } from 'crypto'
import { getLoginOptions } from 'payload/shared'

import type { RawUser } from './mintSession.js'

import { USER_HANDLE_FIELD } from '../shared/constants.js'

const HANDLE = /^[A-Za-z0-9_-]{86}$/

/**
 * The user's WebAuthn user.id (64 random bytes), created on first use with a partial write.
 * Each passkey row keeps its own copy, so losing this to a racing whole-document write-back
 * never orphans a passkey (review L4).
 */
export const ensureUserHandle = async (req: PayloadRequest, collectionSlug: string, user: RawUser): Promise<string> => {
  const existing = user[USER_HANDLE_FIELD]
  if (typeof existing === 'string' && HANDLE.test(existing)) return existing
  const handle = randomBytes(64).toString('base64url')
  await req.payload.db.updateOne({
    collection: collectionSlug,
    data: { [USER_HANDLE_FIELD]: handle },
    id: user.id,
    req,
    returning: false,
  })
  return handle
}

/** user.name (email, or username for username logins) and user.displayName (useAsTitle). */
export const webauthnUserNames = (
  config: SanitizedCollectionConfig,
  user: RawUser,
): { displayName: string; name: string } => {
  const { canLoginWithEmail } = getLoginOptions(config.auth.loginWithUsername)
  const email = typeof user.email === 'string' ? user.email : ''
  const username = typeof user.username === 'string' ? user.username : ''
  const name = (canLoginWithEmail && email) || username || email || String(user.id)
  const titleField = config.admin.useAsTitle
  const title = titleField && titleField !== 'id' ? user[titleField] : undefined
  const displayName = typeof title === 'string' && title.trim() ? title.trim().slice(0, 64) : name
  return { displayName, name }
}

export const isFreshSession = (user: RawUser, sid: string, freshMs: number): boolean => {
  const session = user.sessions?.find((s) => s.id === sid)
  const created = session?.createdAt ? Date.parse(String(session.createdAt)) : Number.NaN
  return Number.isFinite(created) && Date.now() - created <= freshMs
}
```

**Step 5: Write the two endpoints, complete.**

```ts
// src/server/endpoints/registerOptions.ts
import { generateRegistrationOptions } from '@simplewebauthn/server'
import { isoBase64URL } from '@simplewebauthn/server/helpers'

import type { ResolvedOptions } from '../options.js'

import { CEREMONY_TIMEOUT_MS, ENDPOINTS, SUPPORTED_ALGORITHM_IDS } from '../../shared/constants.js'
import { issueChallenge } from '../challenges.js'
import { EndpointError, json, passkeyEndpoint } from '../http.js'
import { logEvent } from '../logging.js'
import { authCollectionConfig, loadRawUser } from '../mintSession.js'
import { listPasskeysOfUser } from '../passkeyRecords.js'
import { ensureUserHandle, isFreshSession, webauthnUserNames } from '../userInfo.js'

export const registerOptionsEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'register.options',
    auth: 'signed-in',
    collectionSlug,
    handler: async ({ req, user }) => {
      const raw = await loadRawUser(req, collectionSlug, user.id)
      if (!raw) throw new EndpointError(401, 'unauthorised')
      if (!isFreshSession(raw, user._sid, options.freshSessionMs)) {
        logEvent(req, options, 'passkeys.reauth_required', { collection: collectionSlug, userId: user.id })
        return json(req, 403, { error: 'reauth_required' })
      }
      const existing = await listPasskeysOfUser(req, options, collectionSlug, user.id)
      if (existing.length >= options.limits.passkeysPerUser) throw new EndpointError(409, 'too_many_passkeys')

      const userHandle = await ensureUserHandle(req, collectionSlug, raw)
      const { displayName, name } = webauthnUserNames(authCollectionConfig(req, collectionSlug), raw)
      const creation = await generateRegistrationOptions({
        attestationType: 'none',
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        excludeCredentials: existing.map((p) => ({ id: p.credentialId, transports: p.transports ?? undefined })),
        extensions: { credProps: true },
        rpID: options.rpID,
        rpName: options.rpName,
        supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
        timeout: CEREMONY_TIMEOUT_MS,
        userDisplayName: displayName,
        userID: isoBase64URL.toBuffer(userHandle),
        userName: name,
      })
      const { setCookie } = await issueChallenge({
        challenge: creation.challenge,
        collection: collectionSlug,
        options,
        req,
        type: 'registration',
        userHandle,
        userId: user.id,
      })
      return json(req, 200, { options: creation }, [setCookie])
    },
    options,
    path: ENDPOINTS.registerOptions,
  })
```

```ts
// src/server/endpoints/reauth.ts
import type { ResolvedOptions } from '../options.js'

import { ENDPOINTS } from '../../shared/constants.js'
import { EndpointError, json, passkeyEndpoint } from '../http.js'
import { logEvent } from '../logging.js'
import { reauthenticate } from '../mintSession.js'

/**
 * Re-entering the password for the fresh-session rule (review H1). A real Payload sign-in for
 * the signed-in user: the identifier comes from the session, never the body; lockout and attempt
 * counting apply; the browser moves to the new session and the old one is revoked.
 */
export const reauthEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'reauth',
    auth: 'signed-in',
    collectionSlug,
    handler: async ({ body, req, user }) => {
      const { password } = body
      if (typeof password !== 'string' || !password || password.length > 1024) {
        throw new EndpointError(400, 'bad_request')
      }
      try {
        const result = await reauthenticate({ collectionSlug, password, previousSid: user._sid, req, userId: user.id })
        logEvent(req, options, 'passkeys.reauthenticated', { collection: collectionSlug, userId: user.id })
        return json(req, 200, result.body, [result.setCookie])
      } catch (error) {
        logEvent(req, options, 'passkeys.reauth_failed', {
          collection: collectionSlug,
          reason: error instanceof Error ? error.name : 'unknown',
          userId: user.id,
        })
        return json(req, 401, { error: 'reauth_failed' })
      }
    },
    options,
    path: ENDPOINTS.reauth,
  })
```

Register both in `src/server/endpoints/index.ts`:

```ts
import type { Endpoint } from 'payload'

import type { ResolvedOptions } from '../options.js'

import { reauthEndpoint } from './reauth.js'
import { registerOptionsEndpoint } from './registerOptions.js'

export const passkeyEndpoints = (options: ResolvedOptions, collectionSlug: string): Endpoint[] => [
  registerOptionsEndpoint(options, collectionSlug),
  reauthEndpoint(options, collectionSlug),
]
```

**Step 6: Run the tests.** Run `pnpm test:int test/int/registerOptions.int.spec.ts`. Expected: PASS (9 tests). If the `pubKeyCredParams` order differs, SimpleWebAuthn keeps the order it is given; fix the constant, not the test.

**Step 7: Commit.**

```bash
git add src/server/passkeyRecords.ts src/server/userInfo.ts src/server/endpoints test/helpers/ceremonies.ts test/int/registerOptions.int.spec.ts
git commit -m "feat: add register/options with the fresh-session rule and password re-authentication"
```

### Task 19: `register/verify` (review L4, M3)

> **Implemented as (2026-11-06):** when the passkey insert itself fails (the unique index on `credentialId` lost a race with a parallel registration of the same credential), the endpoint refuses and logs `passkeys.registration_failed` with reason `duplicate_credential_race`. Rows are written with `authCollection`.

**Files:**
- Create: `src/server/endpoints/registerVerify.ts`, `src/shared/aaguid.ts` (stub until Task 23)
- Modify: `src/server/endpoints/index.ts`
- Test: `test/int/registerVerify.int.spec.ts`

**Step 1: Write the failing test.**

```ts
// test/int/registerVerify.int.spec.ts
import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import config from '../configs/single.js'
import { SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey } from '../helpers/ceremonies.js'
import { insertPasskey } from '../helpers/passkeys.js'
import { findSecretKeys } from '../helpers/secrets.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const setUp = async (authOptions: Partial<Parameters<typeof createSoftAuthenticator>[0]> = {}) => {
  const user = await createUser(payload, 'users')
  const client = await passwordClient(config, 'users', user.email)
  const authenticator = createSoftAuthenticator({ origin: SERVER_URL, ...authOptions })
  return { authenticator, client, user }
}

const rows = (userId: number | string) =>
  payload.find({ collection: 'passkeys', overrideAccess: true, where: { user: { equals: userId } } })

describe('register/verify', () => {
  it('stores a synced passkey and returns only public fields', async () => {
    const { authenticator, client, user } = await setUp({ aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' })
    const { verify } = await registerPasskey(client, authenticator)
    expect(verify!.status).toBe(200)
    expect(findSecretKeys(verify!.json)).toEqual([])
    expect(verify!.json.passkey).toMatchObject({ aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4', backedUp: true, deviceType: 'multiDevice', name: 'Google Password Manager', rpID: 'localhost' })
    const [row] = (await rows(user.id)).docs
    expect(row).toMatchObject({ collection: 'users', counter: 0, credentialId: authenticator.credentialIds()[0], userHandle: (await rawUser(payload, 'users', user.id)).passkeyUserHandle })
    expect(client.cookies.has('payload-passkeys-reg-users')).toBe(false)
  })

  it('stores a device-bound passkey and a chosen name, trimmed', async () => {
    const { authenticator, client, user } = await setUp({ backupEligible: false })
    const { verify } = await registerPasskey(client, authenticator, { name: '  Work laptop \u0007 ' })
    expect(verify!.json.passkey).toMatchObject({ backedUp: false, deviceType: 'singleDevice', name: 'Work laptop' })
    expect((await rows(user.id)).totalDocs).toBe(1)
  })

  it('accepts a missing credProps and refuses rk: false (review L4)', async () => {
    const a = await setUp()
    expect((await registerPasskey(a.client, a.authenticator, { overrides: { credPropsRk: null } })).verify!.status).toBe(200)
    const b = await setUp()
    const refused = await registerPasskey(b.client, b.authenticator, { overrides: { credPropsRk: false } })
    expect(refused.verify!.status).toBe(400)
    expect(refused.verify!.json).toEqual({ error: 'registration_failed' })
  })

  it('refuses a replayed response', async () => {
    const { authenticator, client } = await setUp()
    const first = await registerPasskey(client, authenticator)
    expect(first.verify!.status).toBe(200)
    const again = await client.post('/api/users/passkeys/register/verify', { response: first.response })
    expect(again.json).toEqual({ error: 'registration_failed' })
  })

  it('refuses a credential ID stored for anyone', async () => {
    const { authenticator, client } = await setUp()
    const options = await client.post('/api/users/passkeys/register/options')
    const response = await authenticator.register(options.json.options)
    const other = await createUser(payload, 'users')
    await insertPasskey(payload, { collection: 'users', credentialId: response.id, userId: other.id })
    const res = await client.post('/api/users/passkeys/register/verify', { response })
    expect(res.json).toEqual({ error: 'registration_failed' })
  })
})
```

Run `pnpm test:int test/int/registerVerify.int.spec.ts`. Expected: FAIL (404).

**Step 2: Write the AAGUID stub `src/shared/aaguid.ts`.** Task 23 replaces the map with the generated snapshot.

```ts
const NAMES: Record<string, string> = { 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager' }

export const providerName = (aaguid: null | string | undefined): null | string =>
  (aaguid && NAMES[aaguid.toLowerCase()]) || null
```

**Step 3: Write `src/server/endpoints/registerVerify.ts`, complete.**

```ts
import { verifyRegistrationResponse } from '@simplewebauthn/server'
import { isoBase64URL } from '@simplewebauthn/server/helpers'

import type { ResolvedOptions } from '../options.js'
import type { PasskeyRow } from '../passkeyRecords.js'

import { providerName } from '../../shared/aaguid.js'
import { ENDPOINTS, MAX_PASSKEY_NAME, SUPPORTED_ALGORITHM_IDS } from '../../shared/constants.js'
import { ChallengeRejected, clearChallengeCookie, consumeChallenge } from '../challenges.js'
import { json, passkeyEndpoint } from '../http.js'
import { logEvent } from '../logging.js'
import { findPasskeyByCredentialId, listPasskeysOfUser, toPublicPasskey } from '../passkeyRecords.js'
import { challengeFromClientData, parseRegistrationResponse } from '../webauthnJson.js'

/** Printable text only, collapsed and cut to the field's limit. Empty means "use the default". */
export const cleanPasskeyName = (value: unknown): null | string => {
  if (typeof value !== 'string') return null
  // eslint-disable-next-line no-control-regex
  const clean = value.replace(/[\u0000-\u001f\u007f-\u009f​-‏ -‮⁦-⁩]/g, '').replace(/\s+/g, ' ').trim()
  return clean ? clean.slice(0, MAX_PASSKEY_NAME) : null
}

const ZERO_AAGUID = '00000000-0000-0000-0000-000000000000'

export const registerVerifyEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'register.verify',
    auth: 'signed-in',
    collectionSlug,
    handler: async ({ body, req, user }) => {
      const clear = clearChallengeCookie(options, 'registration', collectionSlug)
      const refuse = (reason: string, credentialId?: string, status = 400) => {
        logEvent(req, options, 'passkeys.registration_failed', { collection: collectionSlug, credentialId, reason, userId: user.id })
        return json(req, status, { error: status === 409 ? 'too_many_passkeys' : 'registration_failed' }, [clear])
      }

      const response = parseRegistrationResponse(body.response)
      if (!response) return refuse('malformed_response')
      const challenge = challengeFromClientData(response.response.clientDataJSON)
      if (!challenge) return refuse('malformed_client_data')

      let record
      try {
        record = await consumeChallenge({ challenge, collection: collectionSlug, options, req, type: 'registration', userId: user.id })
      } catch (error) {
        if (error instanceof ChallengeRejected) return refuse(error.reason)
        throw error
      }
      if (!record.userHandle) return refuse('challenge_without_user_handle')

      if (response.clientExtensionResults?.credProps?.rk === false) return refuse('not_discoverable', response.id)

      let verification
      try {
        verification = await verifyRegistrationResponse({
          expectedChallenge: challenge,
          expectedOrigin: options.origins,
          expectedRPID: options.rpID,
          requireUserVerification: true,
          response,
          supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
        })
      } catch (error) {
        return refuse(`verification_failed: ${error instanceof Error ? error.message.slice(0, 200) : 'unknown'}`, response.id)
      }
      if (!verification.verified) return refuse('not_verified', response.id)
      const info = verification.registrationInfo

      if ((await listPasskeysOfUser(req, options, collectionSlug, user.id)).length >= options.limits.passkeysPerUser) {
        return refuse('too_many_passkeys', info.credential.id, 409)
      }
      if (await findPasskeyByCredentialId(req, options, info.credential.id)) {
        return refuse('duplicate_credential', info.credential.id)
      }

      const aaguid = info.aaguid && info.aaguid !== ZERO_AAGUID ? info.aaguid : null
      let row: PasskeyRow
      try {
        row = (await req.payload.create({
          collection: options.slugs.passkeys as never,
          data: {
            aaguid,
            backedUp: info.credentialBackedUp,
            collection: collectionSlug,
            counter: info.credential.counter,
            credentialId: info.credential.id,
            deviceType: info.credentialDeviceType,
            lastUsedAt: null,
            name: cleanPasskeyName(body.name) ?? providerName(aaguid) ?? 'Passkey',
            publicKey: isoBase64URL.fromBuffer(info.credential.publicKey),
            rpID: options.rpID,
            transports: info.credential.transports ?? response.response.transports ?? [],
            user: options.collections.length === 1 ? user.id : { relationTo: collectionSlug, value: user.id },
            userHandle: record.userHandle,
          } as never,
          depth: 0,
          overrideAccess: true,
          req,
        })) as unknown as PasskeyRow
      } catch {
        // The unique index on credentialId lost a race with a parallel registration.
        return refuse('duplicate_credential', info.credential.id)
      }

      logEvent(req, options, 'passkeys.registered', { aaguid, collection: collectionSlug, credentialId: row.credentialId, userId: user.id })
      return json(req, 200, { passkey: toPublicPasskey(row) }, [clear])
    },
    options,
    path: ENDPOINTS.registerVerify,
  })
```

Add `registerVerifyEndpoint(options, collectionSlug)` to the list in `src/server/endpoints/index.ts`.

**Step 4: Run the tests.** Run `pnpm test:int test/int/registerVerify.int.spec.ts`. Expected: PASS (5 tests).

**Step 5: Commit.**

```bash
git add src/server/endpoints src/shared/aaguid.ts test/int/registerVerify.int.spec.ts
git commit -m "feat: verify and store new passkeys"
```

### Task 20: `sign-in/options` and `sign-in/verify` (review H3, L4, L6, M2, M5, M7)

> **Implemented as (2026-11-06):** the collection check reads `row.authCollection`. An unknown credential returns the generic 400 plus `unknownCredential: true` so the client can call `signalUnknownCredential`: the one documented exception to identical failures (design §4.2, §6).

**Files:**
- Create: `src/server/endpoints/signInOptions.ts`, `src/server/endpoints/signInVerify.ts`
- Modify: `src/server/endpoints/index.ts`
- Test: `test/int/signIn.int.spec.ts`

**Step 1: Write the failing test.** The happy paths and the M5/M7 rules. The full rejection matrix is Task 31.

```ts
// test/int/signIn.int.spec.ts
import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { testHooks } from '../../dev/testHooks.js'
import config from '../configs/single.js'
import { createClient, SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey, signInWithPasskey } from '../helpers/ceremonies.js'
import { findSecretKeys } from '../helpers/secrets.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})
beforeEach(() => testHooks.reset())

const enrolled = async (authOptions: Partial<Parameters<typeof createSoftAuthenticator>[0]> = {}) => {
  const user = await createUser(payload, 'users')
  const authenticator = createSoftAuthenticator({ origin: SERVER_URL, ...authOptions })
  const { verify } = await registerPasskey(await passwordClient(config, 'users', user.email), authenticator)
  expect(verify!.status).toBe(200)
  return { authenticator, user }
}

const row = async (credentialId: string) =>
  (await payload.find({ collection: 'passkeys', overrideAccess: true, where: { credentialId: { equals: credentialId } } })).docs[0]!

describe('sign-in/options', () => {
  it('names no credentials and requires UV', async () => {
    const client = createClient(config)
    const res = await client.post('/api/users/passkeys/sign-in/options')
    expect(res.status).toBe(200)
    expect(res.json.options).toMatchObject({ allowCredentials: [], rpId: 'localhost', timeout: 300_000, userVerification: 'required' })
    expect(client.cookies.has('payload-passkeys-auth-users')).toBe(true)
  })

  it('answers 429 busy at the anonymous cap (test config: 50)', async () => {
    for (let i = 0; i < 50; i++) await createClient(config).post('/api/users/passkeys/sign-in/options')
    const res = await createClient(config).post('/api/users/passkeys/sign-in/options')
    expect(res.status).toBe(429)
    expect(res.json).toEqual({ error: 'busy' })
    await payload.db.deleteMany({ collection: 'passkey-challenges', where: {} })
  })
})

describe('sign-in/verify', () => {
  it('signs in with a native session cookie and the body setUser expects', async () => {
    const { authenticator, user } = await enrolled()
    const client = createClient(config)
    const { verify } = await signInWithPasskey(client, authenticator)
    expect(verify!.status).toBe(200)
    expect(verify!.json).toMatchObject({ exp: expect.any(Number), user: { email: user.email, id: user.id } })
    expect(findSecretKeys(verify!.json)).toEqual([])
    expect(client.cookies.has('payload-token')).toBe(true)
    expect(client.cookies.has('payload-passkeys-auth-users')).toBe(false)
    expect((await client.get('/api/users/me')).json.user.id).toBe(user.id)
    expect((await row(authenticator.credentialIds()[0]!)).lastUsedAt).toBeTruthy()
  })

  it('gives an unknown credential a generic failure plus the hint for signalUnknownCredential', async () => {
    const { authenticator } = await enrolled()
    await payload.db.deleteMany({ collection: 'passkeys', where: { credentialId: { equals: authenticator.credentialIds()[0] } } })
    const { verify } = await signInWithPasskey(createClient(config), authenticator)
    expect(verify!.status).toBe(400)
    expect(verify!.json).toEqual({ error: 'sign_in_failed', unknownCredential: true })
  })

  it('refuses an assertion whose userHandle is not the row\'s (review L4)', async () => {
    const { authenticator } = await enrolled()
    const { verify } = await signInWithPasskey(createClient(config), authenticator, { overrides: { userHandle: 'b3RoZXI' } })
    expect(verify!.json).toEqual({ error: 'sign_in_failed' })
  })

  it('signs in a password-locked user, logs it and resets attempts (review M5)', async () => {
    const { authenticator, user } = await enrolled()
    await payload.db.updateOne({ collection: 'users', data: { lockUntil: new Date(Date.now() + 600_000).toISOString(), loginAttempts: 5 }, id: user.id, returning: false })
    const { verify } = await signInWithPasskey(createClient(config), authenticator)
    expect(verify!.status).toBe(200)
    expect((await rawUser(payload, 'users', user.id)).loginAttempts).toBe(0)
  })

  it('refuses when a beforeLogin hook throws, and leaves no session', async () => {
    const { authenticator, user } = await enrolled()
    const before = (await rawUser(payload, 'users', user.id)).sessions!.length
    testHooks.beforeLogin = () => {
      throw new Error('no logins on Sundays')
    }
    const { verify } = await signInWithPasskey(createClient(config), authenticator)
    expect(verify!.json).toEqual({ error: 'sign_in_failed' })
    expect((await rawUser(payload, 'users', user.id)).sessions!.length).toBe(before)
  })

  it('passes onSignIn the public passkey', async () => {
    const { authenticator } = await enrolled()
    let seen: unknown
    testHooks.onSignIn = (args) => void (seen = args.passkey)
    await signInWithPasskey(createClient(config), authenticator)
    expect(seen).toMatchObject({ credentialId: authenticator.credentialIds()[0] })
    expect(findSecretKeys(seen)).toEqual([])
  })
})

describe('counter and flags (review M7)', () => {
  it('refuses a device-bound passkey whose counter did not increase', async () => {
    const { authenticator } = await enrolled({ backupEligible: false, incrementCounter: true })
    expect((await signInWithPasskey(createClient(config), authenticator)).verify!.status).toBe(200)
    const replayedCounter = await signInWithPasskey(createClient(config), authenticator, { overrides: { counter: 1 } })
    expect(replayedCounter.verify!.json).toEqual({ error: 'sign_in_failed' })
  })

  it('lets a synced passkey regress without lowering the stored counter', async () => {
    const { authenticator } = await enrolled({ incrementCounter: true })
    await signInWithPasskey(createClient(config), authenticator, { overrides: { counter: 7 } })
    expect((await signInWithPasskey(createClient(config), authenticator, { overrides: { counter: 2 } })).verify!.status).toBe(200)
    expect((await row(authenticator.credentialIds()[0]!)).counter).toBe(7)
  })

  it('refuses a change of device type and follows the backup state', async () => {
    const { authenticator } = await enrolled({ backupState: false })
    expect((await signInWithPasskey(createClient(config), authenticator, { overrides: { backupEligible: false, backupState: false } })).verify!.status).toBe(400)
    expect((await signInWithPasskey(createClient(config), authenticator, { overrides: { backupState: true } })).verify!.status).toBe(200)
    expect((await row(authenticator.credentialIds()[0]!)).backedUp).toBe(true)
  })
})
```

Run `pnpm test:int test/int/signIn.int.spec.ts`. Expected: FAIL (404).

**Step 2: Write `src/server/endpoints/signInOptions.ts`, complete.**

```ts
import { generateAuthenticationOptions } from '@simplewebauthn/server'

import type { ResolvedOptions } from '../options.js'

import { CEREMONY_TIMEOUT_MS, ENDPOINTS } from '../../shared/constants.js'
import { ChallengeCapReached, issueChallenge } from '../challenges.js'
import { json, passkeyEndpoint } from '../http.js'

/** Discoverable sign-in: no account named, nothing about accounts revealed (design §4.2). */
export const signInOptionsEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'sign-in.options',
    auth: 'anonymous',
    collectionSlug,
    handler: async ({ req }) => {
      const request = await generateAuthenticationOptions({
        allowCredentials: [],
        rpID: options.rpID,
        timeout: CEREMONY_TIMEOUT_MS,
        userVerification: 'required',
      })
      try {
        const { setCookie } = await issueChallenge({ challenge: request.challenge, collection: collectionSlug, options, req, type: 'authentication' })
        return json(req, 200, { options: request }, [setCookie])
      } catch (error) {
        if (error instanceof ChallengeCapReached) return json(req, 429, { error: 'busy' })
        throw error
      }
    },
    options,
    path: ENDPOINTS.signInOptions,
  })
```

**Step 3: Write `src/server/endpoints/signInVerify.ts`, complete.**

```ts
import { verifyAuthenticationResponse } from '@simplewebauthn/server'
import { isoBase64URL } from '@simplewebauthn/server/helpers'

import type { ResolvedOptions } from '../options.js'

import { ENDPOINTS } from '../../shared/constants.js'
import { ChallengeRejected, clearChallengeCookie, consumeChallenge } from '../challenges.js'
import { decideCounter } from '../counterPolicy.js'
import { verifyAgainstDummy } from '../dummyCredential.js'
import { json, passkeyEndpoint } from '../http.js'
import { logEvent } from '../logging.js'
import { mintSession, SignInRefused } from '../mintSession.js'
import { findPasskeyByCredentialId, ownerOf, toPublicPasskey } from '../passkeyRecords.js'
import { challengeFromClientData, parseAuthenticationResponse } from '../webauthnJson.js'

export const signInVerifyEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'sign-in.verify',
    auth: 'anonymous',
    collectionSlug,
    handler: async ({ body, req }) => {
      const clear = clearChallengeCookie(options, 'authentication', collectionSlug)
      const base = { collection: collectionSlug }
      /** Every failure looks the same to the browser; the reason goes to the log only. */
      const refuse = (
        reason: string,
        extra: { aaguid?: null | string; credentialId?: string; unknownCredential?: boolean; userId?: number | string } = {},
      ) => {
        const { unknownCredential, ...fields } = extra
        logEvent(req, options, unknownCredential ? 'passkeys.unknown_credential' : 'passkeys.sign_in_failed', { ...base, ...fields, reason })
        return json(req, 400, { error: 'sign_in_failed', ...(unknownCredential ? { unknownCredential: true } : {}) }, [clear])
      }

      const response = parseAuthenticationResponse(body.response)
      if (!response) return refuse('malformed_response')
      const challenge = challengeFromClientData(response.response.clientDataJSON)
      if (!challenge) return refuse('malformed_client_data')

      try {
        await consumeChallenge({ challenge, collection: collectionSlug, options, req, type: 'authentication' })
      } catch (error) {
        if (error instanceof ChallengeRejected) return refuse(error.reason)
        throw error
      }

      const row = await findPasskeyByCredentialId(req, options, response.id)
      if (!row) {
        await verifyAgainstDummy(response, challenge, options)
        return refuse('unknown_credential', { credentialId: response.id, unknownCredential: true })
      }
      const ids = { aaguid: row.aaguid ?? null, credentialId: row.credentialId }

      // Collection first: on SQL, users 7 and customers 7 can both exist (H3).
      if (row.collection !== collectionSlug) {
        await verifyAgainstDummy(response, challenge, options)
        return refuse('wrong_collection', ids)
      }
      const owner = ownerOf(row)
      if (!owner || owner.collection !== collectionSlug) return refuse('owner_mismatch', ids)
      const withUser = { ...ids, userId: owner.id }

      if (!response.response.userHandle || response.response.userHandle !== row.userHandle) {
        return refuse('user_handle_mismatch', withUser)
      }

      let verification
      try {
        verification = await verifyAuthenticationResponse({
          // Counter 0: the library would throw on any non-increase; decideCounter applies the policy (M7).
          credential: {
            counter: 0,
            id: row.credentialId,
            publicKey: isoBase64URL.toBuffer(row.publicKey),
            transports: (row.transports ?? undefined) as never,
          },
          expectedChallenge: challenge,
          expectedOrigin: options.origins,
          expectedRPID: options.rpID,
          requireUserVerification: true,
          response,
        })
      } catch (error) {
        return refuse(`verification_failed: ${error instanceof Error ? error.message.slice(0, 200) : 'unknown'}`, withUser)
      }
      if (!verification.verified) return refuse('bad_signature', withUser)
      const info = verification.authenticationInfo

      const decision = decideCounter(
        { backedUp: Boolean(row.backedUp), counter: row.counter ?? 0, deviceType: row.deviceType },
        { backedUp: info.credentialBackedUp, deviceType: info.credentialDeviceType, newCounter: info.newCounter },
      )
      if (decision.action === 'refuse') return refuse(decision.reason, withUser)
      if (decision.regression) logEvent(req, options, 'passkeys.counter_regression', { ...base, ...withUser })

      await req.payload.db.updateOne({
        collection: options.slugs.passkeys,
        data: { backedUp: decision.backedUp, counter: decision.counter, lastUsedAt: new Date().toISOString() },
        id: row.id,
        req,
        returning: false,
      })

      let minted
      try {
        minted = await mintSession({ collectionSlug, onSignIn: options.onSignIn, passkey: toPublicPasskey(row), req, userId: owner.id })
      } catch (error) {
        const reason = error instanceof SignInRefused ? error.reason : `refused_by_hook: ${error instanceof Error ? error.name : 'unknown'}`
        return refuse(reason, withUser)
      }

      if (minted.wasLocked) logEvent(req, options, 'passkeys.signed_in_while_locked', { ...base, ...withUser })
      logEvent(req, options, 'passkeys.signed_in', { ...base, ...withUser })
      return json(req, 200, minted.body, [minted.setCookie, clear])
    },
    options,
    path: ENDPOINTS.signInVerify,
  })
```

Add both to `src/server/endpoints/index.ts`.

**Step 4: Run the tests.** Run `pnpm test:int test/int/signIn.int.spec.ts`. Expected: PASS (11 tests). Then on SQLite and Postgres. Expected: PASS.

**Step 5: Commit.**

```bash
git add src/server/endpoints test/int/signIn.int.spec.ts
git commit -m "feat: sign in with a discoverable passkey and mint a native session"
```

### Task 21: `status`, `rename` and `delete` (review H3, M6, M9)

> **Implemented as (2026-11-06):** the ownership `where` (`ownPasskeysWhere`) matches `authCollection`, not `collection`.

**Files:**
- Create: `src/server/endpoints/status.ts`, `src/server/endpoints/rename.ts`, `src/server/endpoints/delete.ts`
- Modify: `src/server/endpoints/index.ts`
- Test: `test/int/manage.int.spec.ts`

**Step 1: Write the failing test.**

```ts
// test/int/manage.int.spec.ts
import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import config from '../configs/single.js'
import { createClient, SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey } from '../helpers/ceremonies.js'
import { insertPasskey } from '../helpers/passkeys.js'
import { findSecretKeys } from '../helpers/secrets.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const STATUS = '/api/users/passkeys/status'

describe('status (review M9)', () => {
  it('tells anonymous callers only whether passkeys work here', async () => {
    expect((await createClient(config).post(STATUS)).json).toEqual({ available: true })
    expect((await createClient(config, { origin: 'http://127.0.0.1:3000' }).post(STATUS)).json).toEqual({ available: false })
  })

  it('gives the signed-in owner the reason, the RP ID and their passkeys', async () => {
    const user = await createUser(payload, 'users')
    await insertPasskey(payload, { collection: 'users', userId: user.id })
    const client = await passwordClient(config, 'users', user.email)
    const res = await client.post(STATUS, {}, { headers: { Origin: 'http://127.0.0.1:3000' } })
    expect(res.json).toMatchObject({ available: false, reason: 'origin_not_allowed', rpID: 'localhost' })
    expect(res.json.passkeys).toHaveLength(1)
    expect(res.json.signalUserId).toBeNull()
    expect(findSecretKeys(res.json)).toEqual([])
  })
})

describe('rename', () => {
  it('renames your own passkey and nobody else\'s', async () => {
    const alice = await createUser(payload, 'users')
    const bob = await createUser(payload, 'users')
    const mine = await insertPasskey(payload, { collection: 'users', userId: alice.id })
    const theirs = await insertPasskey(payload, { collection: 'users', userId: bob.id })
    const client = await passwordClient(config, 'users', alice.email)
    expect((await client.post('/api/users/passkeys/rename', { id: mine.id, name: ' Phone ' })).json.passkey.name).toBe('Phone')
    expect((await client.post('/api/users/passkeys/rename', { id: theirs.id, name: 'Mine now' })).status).toBe(404)
    expect((await client.post('/api/users/passkeys/rename', { id: mine.id, name: '   ' })).status).toBe(400)
  })
})

describe('delete (review M6)', () => {
  it('removes your own passkey, and can sign out every other session', async () => {
    const alice = await createUser(payload, 'users')
    const authenticator = createSoftAuthenticator({ origin: SERVER_URL })
    const client = await passwordClient(config, 'users', alice.email)
    const { verify } = await registerPasskey(client, authenticator)
    const other = await passwordClient(config, 'users', alice.email)
    const res = await client.post('/api/users/passkeys/delete', { id: verify!.json.passkey.id, signOutOtherSessions: true })
    expect(res.status).toBe(200)
    expect(res.json).toEqual({ remaining: 0, removed: true, signedOutSessions: 1 })
    expect((await other.get('/api/users/me')).json.user).toBeNull()
    expect((await client.get('/api/users/me')).json.user.id).toBe(alice.id)
    expect((await rawUser(payload, 'users', alice.id)).sessions).toHaveLength(1)
  })

  it('keeps other sessions unless asked', async () => {
    const alice = await createUser(payload, 'users')
    const row = await insertPasskey(payload, { collection: 'users', userId: alice.id })
    const client = await passwordClient(config, 'users', alice.email)
    const other = await passwordClient(config, 'users', alice.email)
    expect((await client.post('/api/users/passkeys/delete', { id: row.id })).json.signedOutSessions).toBe(0)
    expect((await other.get('/api/users/me')).json.user.id).toBe(alice.id)
  })

  it("refuses someone else's passkey with 404", async () => {
    const alice = await createUser(payload, 'users')
    const bob = await createUser(payload, 'users')
    const theirs = await insertPasskey(payload, { collection: 'users', userId: bob.id })
    const client = await passwordClient(config, 'users', alice.email)
    expect((await client.post('/api/users/passkeys/delete', { id: theirs.id })).status).toBe(404)
    expect((await payload.count({ collection: 'passkeys', where: { id: { equals: theirs.id } } })).totalDocs).toBe(1)
  })
})
```

Run `pnpm test:int test/int/manage.int.spec.ts`. Expected: FAIL (404s).

**Step 2: Write the three endpoints, complete.**

```ts
// src/server/endpoints/status.ts
import type { ResolvedOptions } from '../options.js'

import { ENDPOINTS, USER_HANDLE_FIELD } from '../../shared/constants.js'
import { json, passkeyEndpoint } from '../http.js'
import { loadRawUser } from '../mintSession.js'
import { listPasskeysOfUser, toPublicPasskey } from '../passkeyRecords.js'

/**
 * Whether passkeys work at the caller's origin. Anonymous callers learn only that (M9). The
 * signed-in owner also gets the reason, the RP ID, their passkeys (the manager's one read) and
 * `signalUserId`, the WebAuthn user.id that PublicKeyCredential.signalAllAcceptedCredentials needs.
 */
export const statusEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'status',
    auth: 'optional',
    checkOrigin: false,
    collectionSlug,
    handler: async ({ req, user }) => {
      const origin = req.headers.get('Origin')
      const available = origin !== null && options.origins.includes(origin)
      if (!user) return json(req, 200, { available })
      const [rows, raw] = await Promise.all([
        listPasskeysOfUser(req, options, collectionSlug, user.id),
        loadRawUser(req, collectionSlug, user.id),
      ])
      const handle = raw?.[USER_HANDLE_FIELD]
      return json(req, 200, {
        available,
        ...(available ? {} : { reason: origin === null ? 'no_origin' : 'origin_not_allowed' }),
        passkeys: rows.map(toPublicPasskey),
        rpID: options.rpID,
        signalUserId: typeof handle === 'string' ? handle : null,
      })
    },
    options,
    path: ENDPOINTS.status,
  })
```

```ts
// src/server/endpoints/rename.ts
import type { ResolvedOptions } from '../options.js'
import type { PasskeyRow } from '../passkeyRecords.js'

import { ENDPOINTS } from '../../shared/constants.js'
import { EndpointError, json, passkeyEndpoint } from '../http.js'
import { logEvent } from '../logging.js'
import { findOwnPasskey, toPublicPasskey } from '../passkeyRecords.js'
import { cleanPasskeyName } from './registerVerify.js'

export const renameEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'rename',
    auth: 'signed-in',
    collectionSlug,
    handler: async ({ body, req, user }) => {
      const name = cleanPasskeyName(body.name)
      if (!name) throw new EndpointError(400, 'bad_request')
      const row = await findOwnPasskey(req, options, collectionSlug, user.id, body.id)
      if (!row) throw new EndpointError(404, 'not_found')
      const updated = (await req.payload.update({
        collection: options.slugs.passkeys as never,
        data: { name } as never,
        depth: 0,
        id: row.id,
        overrideAccess: true,
        req,
      })) as unknown as PasskeyRow
      logEvent(req, options, 'passkeys.renamed', { collection: collectionSlug, credentialId: row.credentialId, userId: user.id })
      return json(req, 200, { passkey: toPublicPasskey(updated) })
    },
    options,
    path: ENDPOINTS.rename,
  })
```

```ts
// src/server/endpoints/delete.ts
import type { ResolvedOptions } from '../options.js'

import { ownPasskeysWhere } from '../../collections/passkeys.js'
import { ENDPOINTS } from '../../shared/constants.js'
import { EndpointError, json, passkeyEndpoint } from '../http.js'
import { logEvent } from '../logging.js'
import { revokeSessions } from '../mintSession.js'
import { findOwnPasskey, listPasskeysOfUser } from '../passkeyRecords.js'

/**
 * The only way to remove a passkey (REST delete is off). With signOutOtherSessions, every session
 * but this one ends, so removing a planted passkey also ends what it signed in (review M6).
 */
export const deleteEndpoint = (options: ResolvedOptions, collectionSlug: string) =>
  passkeyEndpoint({
    action: 'delete',
    auth: 'signed-in',
    collectionSlug,
    handler: async ({ body, req, user }) => {
      const row = await findOwnPasskey(req, options, collectionSlug, user.id, body.id)
      if (!row) throw new EndpointError(404, 'not_found')
      await req.payload.db.deleteMany({
        collection: options.slugs.passkeys,
        req,
        where: { and: [{ id: { equals: row.id } }, ownPasskeysWhere(options, collectionSlug, user.id)] },
      })
      const signedOutSessions =
        body.signOutOtherSessions === true
          ? await revokeSessions({ collectionSlug, keep: user._sid, req, userId: user.id })
          : 0
      const remaining = (await listPasskeysOfUser(req, options, collectionSlug, user.id)).length
      logEvent(req, options, 'passkeys.removed', {
        collection: collectionSlug,
        credentialId: row.credentialId,
        reason: signedOutSessions ? `signed_out_${signedOutSessions}` : undefined,
        userId: user.id,
      })
      return json(req, 200, { remaining, removed: true, signedOutSessions })
    },
    options,
    path: ENDPOINTS.delete,
  })
```

Add all three to `src/server/endpoints/index.ts`. The final list is: `status`, `register/options`, `register/verify`, `sign-in/options`, `sign-in/verify`, `reauth`, `rename`, `delete`.

**Step 3: Run the tests.** Run `pnpm test:int test/int/manage.int.spec.ts`. Expected: PASS (6 tests).

**Step 4: Commit.**

```bash
git add src/server/endpoints test/int/manage.int.spec.ts
git commit -m "feat: add passkey status, rename and remove endpoints"
```

### Task 22: Translations (`passkeys` namespace, UK English)

**Files:**
- Create: `src/translations/en.ts`, `src/translations/index.ts`
- Modify: `src/index.ts`
- Test: `test/unit/translations.spec.ts`

Payload does not fall back to English for a missing key (Verified facts, "Other facts"), so the English strings are copied into every language the host supports, under the host's own overrides.

**Step 1: Write the failing test.**

```ts
// test/unit/translations.spec.ts
import { describe, expect, it } from 'vitest'

import { en } from '../../src/translations/en.js'
import { withPasskeysTranslations } from '../../src/translations/index.js'

describe('withPasskeysTranslations', () => {
  it('adds English when the host configures nothing', () => {
    expect(withPasskeysTranslations(undefined)?.translations).toEqual({ en })
  })

  it('copies English into every supported or translated language, under host overrides', () => {
    const i18n = withPasskeysTranslations({
      supportedLanguages: { de: {} as never, en: {} as never },
      translations: { de: { passkeys: { signInWithPasskey: 'Mit Passkey anmelden' } }, fr: { general: { x: 'y' } } } as never,
    })
    const translations = i18n!.translations as Record<string, { passkeys: Record<string, string> }>
    expect(translations.de!.passkeys.signInWithPasskey).toBe('Mit Passkey anmelden')
    expect(translations.de!.passkeys.addPasskey).toBe(en.passkeys.addPasskey)
    expect(translations.fr!.passkeys.addPasskey).toBe(en.passkeys.addPasskey)
    expect((translations.fr as unknown as { general: unknown }).general).toEqual({ x: 'y' })
    expect(Object.keys(translations).sort()).toEqual(['de', 'en', 'fr'])
  })
})

describe('English copy', () => {
  const strings = Object.entries(en.passkeys)

  it('uses UK spelling', () => {
    const us = /\b(color|behavior|center|organiz|authoriz|recogniz|customiz|canceled|favorite|analyz)/i
    expect(strings.filter(([, value]) => us.test(value))).toEqual([])
  })

  it('uses curly apostrophes and the ellipsis character consistently', () => {
    expect(strings.filter(([, value]) => value.includes("'") || value.includes('...'))).toEqual([])
  })

  it('names every interpolation it uses', () => {
    for (const [, value] of strings) {
      for (const match of value.matchAll(/\{\{(\w+)\}\}/g)) expect(['count', 'date', 'name', 'rpID']).toContain(match[1])
    }
  })
})
```

Run `pnpm test:unit test/unit/translations.spec.ts`. Expected: FAIL, modules not found.

**Step 2: Write `src/translations/en.ts`, complete.** Typographic apostrophes (’) and the ellipsis character (…) throughout.

```ts
export const en = {
  passkeys: {
    addCancelled: 'No passkey was added.',
    added: 'Passkey added.',
    addFailed: 'The passkey wasn’t added. Try again.',
    adding: 'Waiting for your device…',
    addPasskey: 'Add a passkey',
    alreadyOnDevice: 'This device already has a passkey for your account.',
    alsoSignOut: 'Also sign out everywhere else',
    alsoSignOutHint: 'Ends every other session on this account, including any started with this passkey.',
    busy: 'Passkey sign-in is busy. Try again in a minute, or sign in with your password.',
    cancel: 'Cancel',
    confirm: 'Confirm',
    confirmPasswordBody: 'For your security, enter your password before adding a passkey.',
    confirmPasswordTitle: 'Confirm your password',
    created: 'Added {{date}}',
    dontAskAgain: 'Don’t ask again',
    enrolBody: 'Next time, use your fingerprint, face or device PIN instead of your password.',
    enrolTitle: 'Sign in faster with a passkey',
    genericError: 'Something went wrong. Try again.',
    lastUsed: 'Last used {{date}}',
    madeFor: 'Made for {{rpID}}',
    name: 'Name',
    nameRequired: 'Enter a name.',
    neverUsed: 'Not used yet',
    none: 'You haven’t added a passkey yet.',
    notNow: 'Not now',
    or: 'or',
    password: 'Password',
    rateLimited: 'Too many attempts. Wait a minute and try again.',
    remove: 'Remove',
    removeFailed: 'The passkey wasn’t removed. Try again.',
    removeKeepsOthers: 'Your other passkeys will still work.',
    removeLast: 'This is your only passkey. You can still sign in with your password.',
    removeTitle: 'Remove “{{name}}”?',
    removed: 'Passkey removed.',
    rename: 'Rename',
    renamed: 'Passkey renamed.',
    save: 'Save',
    sectionDescription: 'Sign in with your fingerprint, face or device PIN instead of your password. Your password still works.',
    sectionTitle: 'Passkeys',
    signInCancelled:
      'No passkey was used. If you haven’t added one yet, sign in with your password, then add one from your account.',
    signInFailed: 'That passkey couldn’t be used. Try again or sign in with your password.',
    signingIn: 'Waiting for your passkey…',
    signInUnavailableHere: 'Passkey sign-in isn’t available at this address. Sign in with your password.',
    signInWithPasskey: 'Sign in with a passkey',
    synced: 'Synced',
    thisDeviceOnly: 'This device only',
    tooMany: 'You have the most passkeys allowed. Remove one to add another.',
    unsupportedBrowser: 'This browser can’t use passkeys.',
    worksOnlyOn: 'Passkeys work on {{rpID}} only.',
    wrongPassword: 'That password didn’t work.',
  },
} as const

export type PasskeysTranslationKey = keyof (typeof en)['passkeys']
```

**Step 3: Write `src/translations/index.ts`, complete.**

```ts
import type { Config } from 'payload'

import { en } from './en.js'

type Translations = Record<string, Record<string, unknown>>

export const withPasskeysTranslations = (i18n: Config['i18n']): Config['i18n'] => {
  const existing = (i18n?.translations ?? {}) as Translations
  const languages = new Set(['en', ...Object.keys(i18n?.supportedLanguages ?? {}), ...Object.keys(existing)])
  const translations: Translations = { ...existing }
  for (const language of languages) {
    const current = translations[language] ?? {}
    translations[language] = {
      ...current,
      passkeys: { ...en.passkeys, ...(current.passkeys as Record<string, string> | undefined) },
    }
  }
  return { ...i18n, translations: translations as NonNullable<Config['i18n']>['translations'] }
}
```

In `src/index.ts`, set `i18n: withPasskeysTranslations(incoming.i18n)` on the returned config (whether or not `enabled`).

**Step 4: Run the test.** Run `pnpm test:unit test/unit/translations.spec.ts`. Expected: PASS.

**Step 5: Commit.**

```bash
git add src/translations src/index.ts test/unit/translations.spec.ts
git commit -m "feat: add the passkeys translation namespace in UK English"
```

### Task 23: AAGUID name snapshot

**Files:**
- Create: `scripts/build-aaguids.mjs`, `src/shared/aaguids.generated.ts`
- Modify: `src/shared/aaguid.ts`
- Test: `test/unit/aaguid.spec.ts`

The community list is deprecated: no new entries since 1 November 2026, and it returns `{}` from 6 January 2027. It has **no licence file**, and its icons are vendor logos. So the snapshot vendors **names only** (facts, not artwork), pinned to a commit and a content hash. The manager shows a generic passkey icon (Task 28). Icons are a pre-1.0 checklist decision.

**Step 1: Write the failing test.**

```ts
// test/unit/aaguid.spec.ts
import { describe, expect, it } from 'vitest'

import { providerName } from '../../src/shared/aaguid.js'
import { AAGUID_NAMES } from '../../src/shared/aaguids.generated.js'

describe('providerName', () => {
  it.each([
    ['ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4', 'Google Password Manager'],
    ['fbfc3007-154e-4ecc-8c0b-6e020557d7bd', 'Apple Passwords'],
    ['bada5566-a7aa-401f-bd96-45619a55120d', '1Password'],
    ['08987058-cadc-4b81-b6e1-30de50dcbe96', 'Windows Hello'],
    ['EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4', 'Google Password Manager'],
  ])('names %s', (aaguid, name) => {
    expect(providerName(aaguid)).toBe(name)
  })
  it('returns null for unknown, zero and missing AAGUIDs', () => {
    expect(providerName('00000000-0000-0000-0000-000000000000')).toBeNull()
    expect(providerName('12345678-1234-1234-1234-123456789abc')).toBeNull()
    expect(providerName(null)).toBeNull()
  })
  it('vendors the agreed providers and nothing else', () => {
    expect(new Set(Object.values(AAGUID_NAMES)).size).toBe(20)
  })
})
```

Run `pnpm test:unit test/unit/aaguid.spec.ts`. Expected: FAIL, "Cannot find module '../../src/shared/aaguids.generated.js'".

**Step 2: Write `scripts/build-aaguids.mjs`, complete.**

```js
// Regenerates src/shared/aaguids.generated.ts from a pinned commit of the community list.
// Run: pnpm build:aaguids. Change COMMIT and SHA256 together, after reading the diff.
import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'

const COMMIT = 'd53c0f358deeec6ba23d6c6e1f25f32ce45c22f9'
const SHA256 = '2975a91ab5d24878bab9c7d4dc2341408cd013052a7a936921ca6117f551f075'
const LIST_URL = `https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/${COMMIT}/aaguid.json`
const PROVIDERS = new Set([
  '1Password',
  'Apple Passwords',
  'Bitwarden',
  'Chrome on Mac',
  'Dashlane',
  'Devolutions',
  'Edge on Mac',
  'Enpass',
  'Google Password Manager',
  'iCloud Keychain (Managed)',
  'IDmelon',
  'KeePassXC',
  'Keeper',
  'LastPass',
  'Microsoft Password Manager',
  'NordPass',
  'Proton Pass',
  'Samsung Pass',
  'Windows Hello',
  'Zoho Vault',
])

const body = Buffer.from(await (await fetch(LIST_URL)).arrayBuffer())
const hash = createHash('sha256').update(body).digest('hex')
if (hash !== SHA256) throw new Error(`aaguid.json hash ${hash} is not the pinned ${SHA256}`)
const list = JSON.parse(body.toString('utf8'))
if (Object.keys(list).length === 0) throw new Error('The community list is empty (it was retired). Keep the existing snapshot.')

const names = Object.fromEntries(
  Object.entries(list)
    .filter(([aaguid, entry]) => /^[0-9a-f-]{36}$/.test(aaguid) && PROVIDERS.has(entry.name))
    .map(([aaguid, entry]) => [aaguid, entry.name])
    .sort(([a], [b]) => a.localeCompare(b)),
)
const missing = [...PROVIDERS].filter((name) => !Object.values(names).includes(name))
if (missing.length) throw new Error(`Not in the list: ${missing.join(', ')}`)

writeFileSync(
  new URL('../src/shared/aaguids.generated.ts', import.meta.url),
  `// Generated by scripts/build-aaguids.mjs from passkeydeveloper/passkey-authenticator-aaguids@${COMMIT}.\n` +
    `// Names only. Do not edit by hand.\nexport const AAGUID_NAMES: Readonly<Record<string, string>> = ${JSON.stringify(names, null, 2)}\n`,
)
console.log(`Wrote ${Object.keys(names).length} AAGUIDs for ${PROVIDERS.size} providers.`)
```

**Step 3: Generate the snapshot and point `providerName` at it.**

Run `pnpm build:aaguids`. Expected: "Wrote 22 AAGUIDs for 20 providers." (Windows Hello has three.) Then replace `src/shared/aaguid.ts`:

```ts
import { AAGUID_NAMES } from './aaguids.generated.js'

/** A display name for the passkey's provider, or null. Display only: never a security decision. */
export const providerName = (aaguid: null | string | undefined): null | string =>
  (aaguid && AAGUID_NAMES[aaguid.toLowerCase()]) || null
```

**Step 4: Run the test.** Run `pnpm test:unit test/unit/aaguid.spec.ts`. Expected: PASS.

**Step 5: Commit.**

```bash
git add scripts/build-aaguids.mjs src/shared/aaguids.generated.ts src/shared/aaguid.ts test/unit/aaguid.spec.ts
git commit -m "feat: name passkeys from a pinned AAGUID snapshot"
```

### Task 24: Recovery CLI `payload passkeys:reset` (review M6)

> **Implemented as (2026-11-06):** the challenge clean-up matches `authCollection`. The command accepts `--email` or `--id`, removes passkeys and pending registration challenges, ends every session, exits 1 on failure and 2 on a usage error, and is registered even with `enabled: false`.

**Files:**
- Create: `src/server/reset.ts`, `src/bin/reset.ts`
- Modify: `src/index.ts`
- Test: `test/int/reset.int.spec.ts`

**Step 1: Write the failing test.**

```ts
// test/int/reset.int.spec.ts
import type { Payload } from 'payload'

import { execFile } from 'child_process'
import { getPayload } from 'payload'
import { promisify } from 'util'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { resetPasskeys } from '../../src/server/reset.js'
import config from '../configs/single.js'
import { passwordClient } from '../helpers/ceremonies.js'
import { insertPasskey } from '../helpers/passkeys.js'
import { createUser, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

describe('resetPasskeys', () => {
  it('removes every passkey and every session of one user only', async () => {
    const alice = await createUser(payload, 'users')
    const bob = await createUser(payload, 'users')
    await insertPasskey(payload, { collection: 'users', userId: alice.id })
    await insertPasskey(payload, { collection: 'users', userId: alice.id })
    await insertPasskey(payload, { collection: 'users', userId: bob.id })
    const signedIn = await passwordClient(config, 'users', alice.email)

    const result = await resetPasskeys({ collection: 'users', email: alice.email.toUpperCase(), payload })
    expect(result).toEqual({ removedPasskeys: 2, removedSessions: 1, userId: alice.id })
    expect((await signedIn.get('/api/users/me')).json.user).toBeNull()
    expect((await rawUser(payload, 'users', alice.id)).sessions ?? []).toHaveLength(0)
    expect((await payload.count({ collection: 'passkeys', where: { user: { equals: bob.id } } })).totalDocs).toBe(1)
  })

  it('refuses an unknown user or collection', async () => {
    await expect(resetPasskeys({ collection: 'users', email: 'nobody@example.test', payload })).rejects.toThrow(/No users user/)
    await expect(resetPasskeys({ collection: 'posts', email: 'x@example.test', payload })).rejects.toThrow(/not a passkeys collection/)
  })

  it('is registered as a Payload bin script', async () => {
    const entry = (await config).bin?.find((b) => b.key === 'passkeys:reset')
    expect(entry?.scriptPath).toMatch(/[/\\]bin[/\\]reset\.(ts|js)$/)
  })
})

describe('the CLI', () => {
  it('runs through `payload passkeys:reset`', async () => {
    const alice = await createUser(payload, 'users')
    await insertPasskey(payload, { collection: 'users', userId: alice.id })
    const { stdout } = await promisify(execFile)(
      'pnpm',
      ['dev:payload', 'passkeys:reset', '--collection', 'users', '--email', alice.email],
      { env: { ...process.env, PAYLOAD_DROP_DATABASE: 'false' }, timeout: 90_000 },
    )
    expect(stdout).toMatch(/Removed 1 passkey and signed out 0 sessions/)
    expect((await payload.count({ collection: 'passkeys', where: { user: { equals: alice.id } } })).totalDocs).toBe(0)
  }, 120_000)
})
```

Run `pnpm test:int test/int/reset.int.spec.ts`. Expected: FAIL, module not found.

**Step 2: Write `src/server/reset.ts`, complete.**

```ts
import type { Payload } from 'payload'

import { createLocalReq } from 'payload'

import { ownPasskeysWhere } from '../collections/passkeys.js'
import { getPasskeysOptions } from './context.js'
import { revokeSessions } from './mintSession.js'

/**
 * For a site owner locked out of their passkeys. Removes the user's passkeys and pending
 * registrations, and always ends every session, so a planted passkey's sessions go too (M6).
 * The password and forgot-password are untouched.
 */
export const resetPasskeys = async ({
  collection,
  email,
  id,
  payload,
}: {
  collection: string
  email?: string
  id?: string
  payload: Payload
}): Promise<{ removedPasskeys: number; removedSessions: number; userId: number | string }> => {
  const options = getPasskeysOptions(payload)
  if (!options.collections.includes(collection)) {
    throw new Error(`"${collection}" is not a passkeys collection. Use one of: ${options.collections.join(', ')}.`)
  }
  if (!email && !id) throw new Error('Give --email or --id.')
  const where = id ? { id: { equals: id } } : { email: { equals: email!.trim().toLowerCase() } }
  const { docs } = await payload.find({ collection: collection as never, depth: 0, limit: 2, overrideAccess: true, where })
  if (docs.length !== 1) throw new Error(`No ${collection} user matches ${id ? `id ${id}` : email}.`)
  const userId = (docs[0] as { id: number | string }).id

  const req = await createLocalReq({}, payload)
  const passkeyWhere = ownPasskeysWhere(options, collection, userId)
  const { totalDocs: removedPasskeys } = await payload.db.count({ collection: options.slugs.passkeys, req, where: passkeyWhere })
  await payload.db.deleteMany({ collection: options.slugs.passkeys, req, where: passkeyWhere })
  await payload.db.deleteMany({
    collection: options.slugs.challenges,
    req,
    where: { and: [{ collection: { equals: collection } }, { userId: { equals: String(userId) } }] },
  })
  const removedSessions = await revokeSessions({ collectionSlug: collection, req, userId })
  payload.logger.info({ collection, event: 'passkeys.reset', msg: 'passkeys.reset', removedPasskeys, removedSessions, userId })
  return { removedPasskeys, removedSessions, userId }
}
```

**Step 3: Write `src/bin/reset.ts`, complete.** Payload's CLI imports this file and calls `script(config)`, with `process.argv[2]` being `passkeys:reset` (`PL/bin/index.js:91-108`). Payload logs a failure but still exits 0, so the script sets the exit code itself.

```ts
import type { SanitizedConfig } from 'payload'

import { getPayload } from 'payload'
import { parseArgs } from 'util'

import { resetPasskeys } from '../server/reset.js'

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

export const script = async (config: SanitizedConfig): Promise<void> => {
  const { values } = parseArgs({
    allowPositionals: true,
    args: process.argv.slice(3),
    options: { collection: { type: 'string' }, email: { type: 'string' }, id: { type: 'string' } },
  })
  if (!values.collection || (!values.email && !values.id)) {
    console.error('Usage: payload passkeys:reset --collection <slug> (--email <email> | --id <id>)')
    process.exit(2)
  }
  const payload = await getPayload({ config })
  try {
    const result = await resetPasskeys({ collection: values.collection, email: values.email, id: values.id, payload })
    console.log(
      `Removed ${plural(result.removedPasskeys, 'passkey', 'passkeys')} and signed out ${plural(result.removedSessions, 'session', 'sessions')} for ${values.collection} ${String(result.userId)}. Their password still works.`,
    )
    process.exit(0)
  } catch (error) {
    console.error(error instanceof Error ? error.message : error)
    process.exit(1)
  }
}
```

(The test expects "signed out 0 sessions"; `plural(0, …)` gives "0 sessions". Good.)

**Step 4: Register the script in `src/index.ts`.**

```ts
import { existsSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const here = path.dirname(fileURLToPath(import.meta.url))
/** dist/bin/reset.js when published, src/bin/reset.ts in this repo. */
const resetScriptPath = ['bin/reset.js', 'bin/reset.ts'].map((file) => path.join(here, file)).find((file) => existsSync(file))
```

In the returned config, add `bin: [...(incoming.bin ?? []), ...(resetScriptPath ? [{ key: 'passkeys:reset', scriptPath: resetScriptPath }] : [])]`. The script is registered even when `enabled: false`, because recovery must always work.

**Step 5: Run the tests.** Run `pnpm test:int test/int/reset.int.spec.ts`. Expected: PASS (4 tests).

**Step 6: Commit.**

```bash
git add src/server/reset.ts src/bin/reset.ts src/index.ts test/int/reset.int.spec.ts
git commit -m "feat: add the passkeys:reset recovery command"
```

### Task 25: Boot checks and log lines (review M2, M3, M4, M9)

**Files:**
- Create: `src/server/boot.ts`
- Modify: `src/index.ts`
- Test: `test/int/boot.int.spec.ts`

**Step 1: Write the failing test.**

```ts
// test/int/boot.int.spec.ts
import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

import { bootPasskeys } from '../../src/server/boot.js'
import { getPasskeysOptions } from '../../src/server/context.js'
import config from '../configs/single.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

describe('bootPasskeys', () => {
  it('logs the resolved RP ID and origins', async () => {
    const info = vi.spyOn(payload.logger, 'info')
    await bootPasskeys(payload, getPasskeysOptions(payload))
    expect(info).toHaveBeenCalledWith(expect.objectContaining({ origins: ['http://localhost:3000'], rpID: 'localhost' }))
  })

  it('warns in production when rateLimit is left at its default (review M2)', async () => {
    const warn = vi.spyOn(payload.logger, 'warn')
    vi.stubEnv('NODE_ENV', 'production')
    try {
      await bootPasskeys(payload, getPasskeysOptions(payload))
    } finally {
      vi.unstubAllEnvs()
    }
    expect(warn).toHaveBeenCalledWith(expect.objectContaining({ msg: expect.stringMatching(/rateLimit/) }))
  })

  it.runIf((process.env.DATABASE_ADAPTER ?? 'mongo') === 'mongo')(
    'rebuilds the unique index replay protection depends on (review M3)',
    async () => {
      const model = (payload.db as unknown as { collections: Record<string, { collection: { dropIndexes: () => Promise<unknown>; indexes: () => Promise<{ key: Record<string, number>; unique?: boolean }[]> } }> }).collections['passkey-challenge-uses']!
      await model.collection.dropIndexes()
      await bootPasskeys(payload, getPasskeysOptions(payload))
      const indexes = await model.collection.indexes()
      expect(indexes.some((index) => index.key.challenge === 1 && index.unique)).toBe(true)
    },
  )
})
```

Run `pnpm test:int test/int/boot.int.spec.ts`. Expected: FAIL, module not found.

**Step 2: Write `src/server/boot.ts`, complete.**

```ts
import type { Payload } from 'payload'

import type { ResolvedOptions } from './options.js'

type MongooseModel = { collection?: { indexes?: () => Promise<{ key: Record<string, number>; unique?: boolean }[]> }; createIndexes?: () => Promise<unknown> }

/**
 * On MongoDB, single use rests on the unique index on passkey-challenge-uses.challenge. Mongoose
 * builds indexes in the background at first boot (autoIndex, db-mongodb connect.js) unless
 * `ensureIndexes` is on, so build them now and check, before the first sign-in can race it.
 */
const ensureReplayIndex = async (payload: Payload, options: ResolvedOptions): Promise<void> => {
  if (payload.db.name !== 'mongoose') return
  const models = (payload.db as unknown as { collections?: Record<string, MongooseModel> }).collections
  for (const slug of [options.slugs.challengeUses, options.slugs.challenges, options.slugs.passkeys]) {
    const model = models?.[slug]
    if (!model?.createIndexes) continue
    try {
      await model.createIndexes()
    } catch (error) {
      payload.logger.error({ err: error, msg: `passkeys: could not build the indexes on ${slug}` })
    }
  }
  const uses = models?.[options.slugs.challengeUses]
  const indexes = (await uses?.collection?.indexes?.().catch(() => [])) ?? []
  if (!indexes.some((index) => index.key.challenge === 1 && index.unique)) {
    payload.logger.error({
      msg: `passkeys: the unique index on ${options.slugs.challengeUses}.challenge is missing, so a challenge could be used twice. Check the database user can create indexes.`,
    })
  }
}

export const bootPasskeys = async (payload: Payload, options: ResolvedOptions): Promise<void> => {
  payload.logger.info({
    collections: options.collections,
    enabled: options.enabled,
    msg: 'passkeys: ready',
    origins: options.origins,
    rpID: options.rpID,
  })
  for (const warning of options.warnings) payload.logger.warn({ msg: `passkeys: ${warning}` })
  if (process.env.NODE_ENV === 'production' && options.rateLimitIsDefault) {
    payload.logger.warn({
      msg: 'passkeys: no rateLimit hook is set. Payload has no IP rate limiter of its own; pass `rateLimit` (see the README for Vercel WAF and Upstash examples).',
    })
  }
  await ensureReplayIndex(payload, options)
}
```

**Step 3: Wire it in `src/index.ts`.** In the returned config:

```ts
onInit: async (payload) => {
  await bootPasskeys(payload, resolved)
  if (incoming.onInit) await incoming.onInit(payload)
},
```

**Step 4: Run the tests.** Run `pnpm test:int test/int/boot.int.spec.ts`, then on SQLite and Postgres (the index test is skipped there; their unique constraints come from the schema push or the migration). Expected: PASS.

**Step 5: Run the whole suite on all three adapters.** This is the M2 gate.

```bash
pnpm test:unit
pnpm test:int
DATABASE_ADAPTER=sqlite pnpm test:int
DATABASE_ADAPTER=postgres pnpm test:int
```

Expected: all PASS.

**Step 6: Commit.**

```bash
git add src/server/boot.ts src/index.ts test/int/boot.int.spec.ts
git commit -m "feat: log the resolved RP ID at boot and make sure the replay index exists"
```

## Milestone M3: admin UI

End state: on the dev app, an admin can sign in with a passkey from the login page; add, rename and remove passkeys on their account page; and see the enrolment prompt after a password sign-in. All copy comes from the `passkeys` namespace.

UI rules for every component in this milestone:
- `'use client'` at the top of every file under `src/components/` except `PasskeysManagerField` (RSC).
- Imports: `@payloadcms/ui`, `@simplewebauthn/browser`, `react`, `payload/shared`, relative `src/shared/*` and `src/components/*`, and `import type` from anywhere. `next/navigation.js` is imported **only** in `src/components/shared/navigation.ts`. The boundary test (Task 4) enforces this.
- Styling: Payload's own CSS variables (`--theme-elevation-*`, `--base`, `--style-radius-s`) in one `src/components/passkeys.css`, imported by each entry component. Class names are `passkeys-*`, so they can't collide.
- Every request goes to the same origin: `${config.routes.api}/${collectionSlug}/passkeys/...`, never `serverURL`, so a preview host never posts to production.
- Errors are shown with `role="alert"`; progress with `aria-live="polite"`; every button keeps its visible label while busy and gets `aria-busy`.

### Task 26: Client plumbing: API, navigation, translations hook and the ceremony flows

**Files:**
- Create: `src/components/shared/api.ts`, `src/components/shared/navigation.ts`, `src/components/shared/usePasskeysT.ts`, `src/components/shared/flows.ts`, `src/components/shared/enrolmentStorage.ts`
- Test: `test/unit/flows.spec.ts`, `test/unit/enrolmentStorage.spec.ts`

The flows take the browser functions and the API as arguments, so they are tested in Node without a browser; the components stay thin.

**Step 1: Write the failing tests.**

```ts
// test/unit/flows.spec.ts
import { describe, expect, it, vi } from 'vitest'

import type { Api, Browser } from '../../src/components/shared/flows.js'

import { registerFlow, signInFlow, syncAcceptedCredentials } from '../../src/components/shared/flows.js'

const reply = (status: number, data: Record<string, unknown> = {}) => ({ data, ok: status < 400, status })
const browser = (overrides: Partial<Browser> = {}): Browser => ({
  sendSignal: vi.fn(async () => undefined),
  startAuthentication: vi.fn(async () => ({ id: 'cred' }) as never),
  startRegistration: vi.fn(async () => ({ id: 'cred' }) as never),
  ...overrides,
})
const cancelled = Object.assign(new Error('The operation either timed out or was not allowed.'), { name: 'NotAllowedError' })

describe('signInFlow', () => {
  it('returns the session body on success', async () => {
    const api: Api = vi.fn(async (path) => (path.endsWith('/options') ? reply(200, { options: { challenge: 'c', rpId: 'localhost' } }) : reply(200, { exp: 1, user: { id: 1 } })))
    expect(await signInFlow({ api, browser: browser() })).toEqual({ body: { exp: 1, user: { id: 1 } }, ok: true })
  })

  it('says cancelled when the person dismisses the prompt', async () => {
    const api: Api = vi.fn(async () => reply(200, { options: { rpId: 'localhost' } }))
    expect(await signInFlow({ api, browser: browser({ startAuthentication: vi.fn(async () => Promise.reject(cancelled)) }) })).toEqual({ message: 'signInCancelled', ok: false })
  })

  it('signals an unknown credential and shows the generic failure', async () => {
    const b = browser()
    const api: Api = vi.fn(async (path) => (path.endsWith('/options') ? reply(200, { options: { rpId: 'localhost' } }) : reply(400, { error: 'sign_in_failed', unknownCredential: true })))
    expect(await signInFlow({ api, browser: b })).toEqual({ message: 'signInFailed', ok: false })
    expect(b.sendSignal).toHaveBeenCalledWith({ credentialID: 'cred', rpID: 'localhost', signalName: 'unknownCredential' })
  })

  it('maps busy and rate limits', async () => {
    expect(await signInFlow({ api: vi.fn(async () => reply(429, { error: 'busy' })), browser: browser() })).toEqual({ message: 'busy', ok: false })
    expect(await signInFlow({ api: vi.fn(async () => reply(429, { error: 'rate_limited' })), browser: browser() })).toEqual({ message: 'rateLimited', ok: false })
  })
})

describe('registerFlow', () => {
  it('asks for the password when the session is stale, then registers', async () => {
    const calls: string[] = []
    let fresh = false
    const api: Api = vi.fn(async (path, body) => {
      calls.push(path)
      if (path.endsWith('/register/options')) return fresh ? reply(200, { options: {} }) : reply(403, { error: 'reauth_required' })
      if (path.endsWith('/reauth')) return (body as { password: string }).password === 'right' ? ((fresh = true), reply(200, { exp: 2, user: { id: 1 } })) : reply(401, { error: 'reauth_failed' })
      return reply(200, { passkey: { id: 9 } })
    })
    const askPassword = vi.fn().mockResolvedValueOnce('wrong').mockResolvedValueOnce('right')
    const onReauthenticated = vi.fn()
    const result = await registerFlow({ api, askPassword, browser: browser(), onReauthenticated })
    expect(result).toEqual({ ok: true, passkey: { id: 9 } })
    expect(askPassword.mock.calls).toEqual([[undefined], ['wrongPassword']])
    expect(onReauthenticated).toHaveBeenCalledWith({ exp: 2, user: { id: 1 } })
    expect(calls.map((c) => c.split('/passkeys/')[1])).toEqual(['register/options', 'reauth', 'reauth', 'register/options', 'register/verify'])
  })

  it('stops quietly when the password prompt is dismissed', async () => {
    const api: Api = vi.fn(async () => reply(403, { error: 'reauth_required' }))
    expect(await registerFlow({ api, askPassword: async () => null, browser: browser(), onReauthenticated: vi.fn() })).toEqual({ message: 'addCancelled', ok: false })
  })

  it.each([
    [reply(409, { error: 'too_many_passkeys' }), undefined, 'tooMany'],
    [reply(200, { options: {} }), Object.assign(new Error('x'), { code: 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED', name: 'InvalidStateError' }), 'alreadyOnDevice'],
    [reply(200, { options: {} }), cancelled, 'addCancelled'],
    [reply(200, { options: {} }), new Error('boom'), 'addFailed'],
  ])('maps failures (%#)', async (optionsReply, browserError, message) => {
    const api: Api = vi.fn(async () => optionsReply)
    const b = browser(browserError ? { startRegistration: vi.fn(async () => Promise.reject(browserError)) } : {})
    expect(await registerFlow({ api, askPassword: async () => null, browser: b, onReauthenticated: vi.fn() })).toEqual({ message, ok: false })
  })
})

describe('syncAcceptedCredentials', () => {
  it('sends the signal and never throws', async () => {
    const b = browser({ sendSignal: vi.fn(async () => Promise.reject(new Error('unsupported'))) })
    await expect(syncAcceptedCredentials(b, { credentialIds: ['a'], rpID: 'localhost', userId: 'h' })).resolves.toBeUndefined()
    expect(b.sendSignal).toHaveBeenCalledWith({ allAcceptedCredentialIDs: ['a'], rpID: 'localhost', signalName: 'allAcceptedCredentials', userID: 'h' })
  })
})
```

```ts
// test/unit/enrolmentStorage.spec.ts
import { describe, expect, it } from 'vitest'

import { enrolmentChoice, rememberChoice, shouldOfferEnrolment } from '../../src/components/shared/enrolmentStorage.js'

const store = () => {
  const map = new Map<string, string>()
  return { getItem: (k: string) => map.get(k) ?? null, removeItem: (k: string) => void map.delete(k), setItem: (k: string, v: string) => void map.set(k, v) }
}

describe('enrolment prompt storage', () => {
  const now = new Date('2026-11-06T12:00:00Z')
  it('offers by default, once per browser session', () => {
    const local = store()
    const session = store()
    expect(shouldOfferEnrolment({ collection: 'users', local, now, session, userId: 1 })).toBe(true)
    expect(shouldOfferEnrolment({ collection: 'users', local, now, session, userId: 1 })).toBe(false)
  })
  it('"Not now" hides it for 30 days for that user', () => {
    const local = store()
    rememberChoice(local, 'users', 1, 'not-now', now)
    expect(enrolmentChoice(local, 'users', 1, new Date('2026-12-05T12:00:00Z'))).toBe('not-now')
    expect(enrolmentChoice(local, 'users', 1, new Date('2026-12-06T12:00:01Z'))).toBeNull()
    expect(enrolmentChoice(local, 'users', 2, now)).toBeNull()
  })
  it('"Don\'t ask again" sticks', () => {
    const local = store()
    rememberChoice(local, 'users', 1, 'never', now)
    expect(shouldOfferEnrolment({ collection: 'users', local, now: new Date('2030-01-01'), session: store(), userId: 1 })).toBe(false)
  })
  it('survives storage that throws (private mode)', () => {
    const broken = { getItem: () => { throw new Error('denied') }, removeItem: () => {}, setItem: () => { throw new Error('denied') } }
    expect(shouldOfferEnrolment({ collection: 'users', local: broken, now, session: broken, userId: 1 })).toBe(false)
  })
})
```

Run `pnpm test:unit test/unit/flows.spec.ts test/unit/enrolmentStorage.spec.ts`. Expected: FAIL, modules not found.

**Step 2: Write the shared modules, complete.**

```ts
// src/components/shared/api.ts
'use client'

export type ApiReply = { data: Record<string, unknown> & { error?: string }; ok: boolean; status: number }
export type Api = (path: string, body?: unknown) => Promise<ApiReply>

/** POSTs JSON to /api/<collection>/passkeys/... on this origin, with the session cookie. */
export const createApi =
  (apiRoute: string, collectionSlug: string): Api =>
  async (path, body = {}) => {
    try {
      const res = await fetch(`${apiRoute}/${collectionSlug}${path}`, {
        body: JSON.stringify(body),
        credentials: 'include',
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
```

```ts
// src/components/shared/navigation.ts
'use client'
// The only module that imports next/*. @payloadcms/ui 3.90 exports no router hooks (Verified
// facts Q4); when Payload 4 does, this file is the whole port.
export { useRouter, useSearchParams } from 'next/navigation.js'
```

```ts
// src/components/shared/usePasskeysT.ts
'use client'
import { useTranslation } from '@payloadcms/ui'

import type { PasskeysTranslationKey } from '../../translations/en.js'

export const usePasskeysT = () => {
  const { i18n, t } = useTranslation()
  const translate = t as unknown as (key: string, vars?: Record<string, unknown>) => string
  return {
    language: i18n.language,
    t: (key: PasskeysTranslationKey, vars?: Record<string, number | string>) => translate(`passkeys:${key}`, vars),
  }
}
```

```ts
// src/components/shared/flows.ts
'use client'
import type { sendSignal, startAuthentication, startRegistration } from '@simplewebauthn/browser'

import type { PasskeysTranslationKey } from '../../translations/en.js'
import type { Api } from './api.js'

import { ENDPOINTS } from '../../shared/constants.js'

export type { Api } from './api.js'
export type Browser = {
  sendSignal: typeof sendSignal
  startAuthentication: typeof startAuthentication
  startRegistration: typeof startRegistration
}
type Fail = { message: PasskeysTranslationKey; ok: false }
const fail = (message: PasskeysTranslationKey): Fail => ({ message, ok: false })

const errorName = (error: unknown): string | undefined => {
  const e = error as { cause?: { name?: string }; name?: string } | null
  return e?.cause?.name ?? e?.name
}
const isCancel = (error: unknown): boolean =>
  ['AbortError', 'NotAllowedError'].includes(errorName(error) ?? '') ||
  (error as { code?: string } | null)?.code === 'ERROR_CEREMONY_ABORTED'

const throttled = (reply: { data: { error?: string }; status: number }): Fail | null =>
  reply.status === 429 ? fail(reply.data.error === 'busy' ? 'busy' : 'rateLimited') : null

export const signInFlow = async ({ api, browser }: { api: Api; browser: Browser }): Promise<Fail | { body: Record<string, unknown>; ok: true }> => {
  const options = await api(ENDPOINTS.signInOptions)
  if (!options.ok) return throttled(options) ?? fail('signInFailed')
  const optionsJSON = options.data.options as Parameters<Browser['startAuthentication']>[0]['optionsJSON']
  let response
  try {
    response = await browser.startAuthentication({ optionsJSON })
  } catch (error) {
    return fail(isCancel(error) ? 'signInCancelled' : 'signInFailed')
  }
  const verify = await api(ENDPOINTS.signInVerify, { response })
  if (verify.ok) return { body: verify.data, ok: true }
  if (verify.data.unknownCredential && optionsJSON.rpId) {
    await browser.sendSignal({ credentialID: response.id, rpID: optionsJSON.rpId, signalName: 'unknownCredential' }).catch(() => undefined)
  }
  return throttled(verify) ?? fail('signInFailed')
}

export const registerFlow = async ({
  api,
  askPassword,
  browser,
  name,
  onReauthenticated,
}: {
  api: Api
  /** Shows the password prompt; resolves null when dismissed. The argument is an error to show. */
  askPassword: (error?: PasskeysTranslationKey) => Promise<null | string>
  browser: Browser
  name?: string
  /** The session moved (review H1): hand the new body to useAuth().setUser. */
  onReauthenticated: (body: Record<string, unknown>) => void
}): Promise<Fail | { ok: true; passkey: Record<string, unknown> }> => {
  let options = await api(ENDPOINTS.registerOptions)
  if (options.status === 403 && options.data.error === 'reauth_required') {
    let error: PasskeysTranslationKey | undefined
    for (;;) {
      const password = await askPassword(error)
      if (password === null) return fail('addCancelled')
      const reauth = await api(ENDPOINTS.reauth, { password })
      if (reauth.ok) {
        onReauthenticated(reauth.data)
        break
      }
      const limited = throttled(reauth)
      if (limited) return limited
      error = 'wrongPassword'
    }
    options = await api(ENDPOINTS.registerOptions)
  }
  if (options.status === 409) return fail('tooMany')
  if (!options.ok) return throttled(options) ?? fail('addFailed')

  let response
  try {
    response = await browser.startRegistration({ optionsJSON: options.data.options as never })
  } catch (error) {
    if ((error as { code?: string } | null)?.code === 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED') return fail('alreadyOnDevice')
    return fail(isCancel(error) ? 'addCancelled' : 'addFailed')
  }
  const verify = await api(ENDPOINTS.registerVerify, { name, response })
  if (verify.ok) return { ok: true, passkey: verify.data.passkey as Record<string, unknown> }
  if (verify.status === 409) return fail('tooMany')
  return throttled(verify) ?? fail('addFailed')
}

/** Tells the password manager which passkeys still exist, so removed ones disappear. Best effort. */
export const syncAcceptedCredentials = async (
  browser: Pick<Browser, 'sendSignal'>,
  { credentialIds, rpID, userId }: { credentialIds: string[]; rpID: string; userId: null | string },
): Promise<void> => {
  if (!userId) return
  await browser
    .sendSignal({ allAcceptedCredentialIDs: credentialIds, rpID, signalName: 'allAcceptedCredentials', userID: userId })
    .catch(() => undefined)
}
```

```ts
// src/components/shared/enrolmentStorage.ts
'use client'

type Store = Pick<Storage, 'getItem' | 'removeItem' | 'setItem'>
const NOT_NOW_MS = 30 * 24 * 60 * 60 * 1000
const key = (collection: string, userId: number | string) => `payload-passkeys:enrol:${collection}:${String(userId)}`
const SESSION_KEY = 'payload-passkeys:enrol-seen'

/** 'never', 'not-now' (still within 30 days) or null. */
export const enrolmentChoice = (local: Store, collection: string, userId: number | string, now: Date): 'never' | 'not-now' | null => {
  const value = local.getItem(key(collection, userId))
  if (value === 'never') return 'never'
  if (value?.startsWith('not-now:')) {
    const until = Date.parse(value.slice('not-now:'.length))
    return Number.isFinite(until) && until > now.getTime() ? 'not-now' : null
  }
  return null
}

export const rememberChoice = (local: Store, collection: string, userId: number | string, choice: 'never' | 'not-now', now: Date): void => {
  try {
    local.setItem(key(collection, userId), choice === 'never' ? 'never' : `not-now:${new Date(now.getTime() + NOT_NOW_MS).toISOString()}`)
  } catch {
    // Storage refused (private mode): the prompt simply comes back next session.
  }
}

/** True at most once per browser session, and never after "Don't ask again" or within "Not now". */
export const shouldOfferEnrolment = ({ collection, local, now, session, userId }: { collection: string; local: Store; now: Date; session: Store; userId: number | string }): boolean => {
  try {
    if (session.getItem(SESSION_KEY)) return false
    session.setItem(SESSION_KEY, '1')
    return enrolmentChoice(local, collection, userId, now) === null
  } catch {
    return false
  }
}
```

**Step 3: Run the tests.** Run `pnpm test:unit test/unit/flows.spec.ts test/unit/enrolmentStorage.spec.ts test/unit/clientBoundary.spec.ts`. Expected: PASS. (The boundary test passes because nothing imports these yet; Task 27 connects them to `./client`.)

**Step 4: Commit.**

```bash
git add src/components/shared test/unit/flows.spec.ts test/unit/enrolmentStorage.spec.ts
git commit -m "feat: add the client ceremony flows, API helper and enrolment storage"
```

### Task 27: `SignInWithPasskey` on the login page

**Files:**
- Create: `src/components/SignInWithPasskey/index.tsx`, `src/components/passkeys.css`
- Modify: `src/exports/client.ts`, `src/index.ts`, `dev/app/(payload)/admin/importMap.js` (generated)
- Test: Task 36 (Playwright) covers the behaviour; this task re-runs the boundary test

**Step 1: Write the component, complete.**

```tsx
'use client'
import { Button, useAuth, useConfig } from '@payloadcms/ui'
import { browserSupportsWebAuthn, sendSignal, startAuthentication, startRegistration } from '@simplewebauthn/browser'
import React, { useEffect, useMemo, useState } from 'react'

import '../passkeys.css'
import { safeAdminRedirect } from '../../shared/redirect.js'
import { ENDPOINTS } from '../../shared/constants.js'
import { createApi } from '../shared/api.js'
import { signInFlow } from '../shared/flows.js'
import { useRouter, useSearchParams } from '../shared/navigation.js'
import { usePasskeysT } from '../shared/usePasskeysT.js'

type State = 'checking' | 'hidden' | 'ready' | 'unavailable' | 'working'

export const SignInWithPasskey: React.FC<{ collectionSlug: string }> = ({ collectionSlug }) => {
  const { config } = useConfig()
  const { setUser } = useAuth()
  const router = useRouter()
  const searchParams = useSearchParams()
  const { t } = usePasskeysT()
  const api = useMemo(() => createApi(config.routes.api, collectionSlug), [config.routes.api, collectionSlug])
  const [state, setState] = useState<State>('checking')
  const [error, setError] = useState<null | string>(null)

  useEffect(() => {
    if (!browserSupportsWebAuthn()) return setState('hidden')
    let live = true
    void api(ENDPOINTS.status).then((reply) => {
      if (live) setState(reply.ok && reply.data.available ? 'ready' : 'unavailable')
    })
    return () => {
      live = false
    }
  }, [api])

  if (state === 'checking' || state === 'hidden') return null
  if (state === 'unavailable') return <p className="passkeys-note">{t('signInUnavailableHere')}</p>

  const onClick = async () => {
    setError(null)
    setState('working')
    const result = await signInFlow({ api, browser: { sendSignal, startAuthentication, startRegistration } })
    if (!result.ok) {
      setError(t(result.message))
      return setState('ready')
    }
    setUser(result.body as never)
    router.push(safeAdminRedirect(searchParams.get('redirect'), config.routes.admin))
  }

  return (
    <div className="passkeys-sign-in">
      <div aria-hidden="true" className="passkeys-sign-in__or">
        <span>{t('or')}</span>
      </div>
      <Button aria-busy={state === 'working'} buttonStyle="secondary" className="passkeys-sign-in__button" disabled={state === 'working'} onClick={onClick} size="large" type="button">
        {state === 'working' ? t('signingIn') : t('signInWithPasskey')}
      </Button>
      {error ? (
        <p className="passkeys-error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  )
}
```

If `Button` on the installed minor doesn't take `aria-busy`, wrap it in a `<div aria-busy>`; don't drop it.

`src/components/passkeys.css` holds `.passkeys-sign-in` (full width of the login form, `margin-top: var(--base)`), `.passkeys-sign-in__or` (a centred "or" over a hairline in `--theme-elevation-150`), `.passkeys-note` and `.passkeys-error` (`--theme-error-500`), and the manager and prompt classes added in Tasks 28 and 29.

**Step 2: Export it and register it.**

`src/exports/client.ts`:

```ts
export { SignInWithPasskey } from '../components/SignInWithPasskey/index.js'
```

In `src/index.ts`, when `resolved.enabled` and the admin user collection (`incoming.admin?.user ?? first auth collection`) is in `resolved.collections`, append to `admin.components.afterLogin`:

```ts
{ clientProps: { collectionSlug: adminUserSlug }, path: '@the-digital-stride/payload-passkeys/client#SignInWithPasskey' }
```

**Step 3: Generate the import map, then check.**

```bash
pnpm dev:generate-importmap
pnpm test:unit test/unit/clientBoundary.spec.ts
pnpm typecheck
```

Expected: the import map gains the component, the boundary test passes, and there are no type errors. Then run `pnpm dev`, register a passkey from the browser console (or wait for Task 28), sign out, and check the button appears under the login form on `http://localhost:3000/admin/login` and the "isn't available at this address" note shows on `http://127.0.0.1:3000/admin/login`.

**Step 4: Commit.**

```bash
git add src/components src/exports/client.ts src/index.ts dev/app
git commit -m "feat: add Sign in with a passkey to the admin login page"
```

### Task 28: The Passkeys section on the account page (`ui` field)

**Files:**
- Create: `src/components/PasskeysManagerField/index.tsx` (RSC), `src/components/PasskeysManagerField/shouldRender.ts`, `src/components/PasskeysManager/index.tsx`, `src/components/PasskeysManager/PasskeyRow.tsx`, `src/components/shared/PasswordPrompt.tsx`
- Modify: `src/exports/rsc.ts`, `src/exports/client.ts`, `src/collections/userFields.ts`, `src/index.ts`, `src/components/passkeys.css`
- Test: `test/unit/managerField.spec.ts` (the own-account rule); Task 36 (behaviour)

**Step 1: Write the failing RSC test.**

The rule is a pure function, so it is tested without importing `@payloadcms/ui` (whose stylesheets plain Node can't load).

```ts
// test/unit/managerField.spec.ts
import { describe, expect, it } from 'vitest'

import { shouldRenderManager } from '../../src/components/PasskeysManagerField/shouldRender.js'

const props = (overrides: Record<string, unknown> = {}) =>
  ({ collectionSlug: 'users', id: 1, operation: 'update', req: { user: { collection: 'users', id: 1 } }, ...overrides }) as never

describe('shouldRenderManager', () => {
  it('is true only on your own document', () => {
    expect(shouldRenderManager(props())).toBe(true)
    expect(shouldRenderManager(props({ id: '1' }))).toBe(true)
    expect(shouldRenderManager(props({ id: 2 }))).toBe(false)
    expect(shouldRenderManager(props({ id: undefined, operation: 'create' }))).toBe(false)
    expect(shouldRenderManager(props({ req: { user: { collection: 'customers', id: 1 } } }))).toBe(false)
    expect(shouldRenderManager(props({ req: { user: null } }))).toBe(false)
  })
})
```

Run `pnpm test:unit test/unit/managerField.spec.ts`. Expected: FAIL, module not found.

**Step 2: Write the rule and the RSC wrapper, complete.**

```ts
// src/components/PasskeysManagerField/shouldRender.ts
import type { UIFieldServerProps } from 'payload'

/**
 * Own document only (Verified facts Q2). Compares req.user, not the `user` prop, which has field
 * read access applied. Nothing on create or on anyone else's document.
 */
export const shouldRenderManager = ({ collectionSlug, id, operation, req }: Pick<UIFieldServerProps, 'collectionSlug' | 'id' | 'operation' | 'req'>): boolean => {
  const user = req?.user
  if (operation !== 'update' || id === undefined || id === null) return false
  return Boolean(user && user.collection === collectionSlug && String(user.id) === String(id))
}
```

```tsx
// src/components/PasskeysManagerField/index.tsx
import type { UIFieldServerProps } from 'payload'

import React from 'react'

import { PasskeysManager } from '../PasskeysManager/index.js'
import { shouldRenderManager } from './shouldRender.js'

export const PasskeysManagerField = (props: UIFieldServerProps) =>
  shouldRenderManager(props) ? <PasskeysManager collectionSlug={props.collectionSlug} /> : null
```

`src/exports/rsc.ts`: `export { PasskeysManagerField } from '../components/PasskeysManagerField/index.js'`.

**Step 3: Add the `ui` field.** In `src/collections/userFields.ts`, `withPasskeyFields` appends this field when `options.enabled` is true (drop the unused `extraFields` parameter):

```ts
{
  name: MANAGER_FIELD,
  type: 'ui',
  admin: {
    components: {
      Field: {
        clientProps: { collectionSlug: collection.slug },
        path: '@the-digital-stride/payload-passkeys/rsc#PasskeysManagerField',
      },
    },
    disableListColumn: true,
  },
}
```

**Step 4: Write `PasswordPrompt`, complete.** One modal, used by the manager and the enrolment prompt.

```tsx
// src/components/shared/PasswordPrompt.tsx
'use client'
import { Button, Modal, useModal } from '@payloadcms/ui'
import React, { useCallback, useId, useRef, useState } from 'react'

import type { PasskeysTranslationKey } from '../../translations/en.js'

import { usePasskeysT } from './usePasskeysT.js'

/** `ask(error?)` opens the modal and resolves with the password, or null when dismissed. */
export const usePasswordPrompt = (slug: string) => {
  const { closeModal, openModal } = useModal()
  const { t } = usePasskeysT()
  const id = useId()
  const resolver = useRef<((value: null | string) => void) | null>(null)
  const [error, setError] = useState<PasskeysTranslationKey | undefined>()
  const [password, setPassword] = useState('')

  const ask = useCallback(
    (nextError?: PasskeysTranslationKey) =>
      new Promise<null | string>((resolve) => {
        resolver.current = resolve
        setError(nextError)
        setPassword('')
        openModal(slug)
      }),
    [openModal, slug],
  )

  const finish = (value: null | string) => {
    closeModal(slug)
    resolver.current?.(value)
    resolver.current = null
  }

  const element = (
    <Modal className="passkeys-modal" slug={slug} onClose={() => finish(null)}>
      <form
        aria-labelledby={`${id}-title`}
        className="passkeys-modal__body"
        onSubmit={(event) => {
          event.preventDefault()
          if (password) finish(password)
        }}
      >
        <h2 id={`${id}-title`}>{t('confirmPasswordTitle')}</h2>
        <p>{t('confirmPasswordBody')}</p>
        <label htmlFor={`${id}-password`}>{t('password')}</label>
        <input autoComplete="current-password" autoFocus id={`${id}-password`} onChange={(e) => setPassword(e.target.value)} required type="password" value={password} />
        {error ? (
          <p className="passkeys-error" role="alert">
            {t(error)}
          </p>
        ) : null}
        <div className="passkeys-modal__actions">
          <Button buttonStyle="secondary" onClick={() => finish(null)} type="button">
            {t('cancel')}
          </Button>
          <Button type="submit">{t('confirm')}</Button>
        </div>
      </form>
    </Modal>
  )
  return { ask, element }
}
```

If `Modal` in the installed minor has no `onClose`, close through the Cancel button only and resolve `null` from a `useEffect` that watches `useModal().isModalOpen(slug)` turning false.

**Step 5: Write `PasskeysManager` and `PasskeyRow` to this specification.**

Props: `{ collectionSlug: string }`.

Data: one `POST status` on mount and after every change, giving `{ available, reason?, rpID, passkeys, signalUserId }`. After each load, call `syncAcceptedCredentials` with the listed credential IDs (best effort).

States:

| State | Renders |
|---|---|
| loading | The section heading and a one-line skeleton (`aria-busy="true"`) |
| load failed | `genericError` with `role="alert"` and a button labelled `retry` that reloads |
| WebAuthn unsupported (`!browserSupportsWebAuthn()`) | The list (rename and remove still work) plus `unsupportedBrowser`; no Add button |
| host mismatch (`!available`) | The list plus `worksOnlyOn` with `{{rpID}}`; no Add button |
| ready | Heading `sectionTitle`, `sectionDescription`, the list or `none`, and the Add button |

Each row (`PasskeyRow`):
- A generic passkey icon (an inline 20px SVG key, `aria-hidden`).
- The name, then the provider name from `providerName(aaguid)` when it differs from the name.
- A pill: `synced` when `backedUp`, else `thisDeviceOnly`.
- `created` and `lastUsed` (or `neverUsed`) with `{{date}}` from `Intl.DateTimeFormat(language, { dateStyle: 'medium' })`.
- `madeFor` with `{{rpID}}` when the row's `rpID` differs from the current `rpID`.
- Rename: replaces the name with an `<input maxLength={64}>` labelled `name`, plus Save and Cancel. Enter saves, Esc cancels. An empty value shows `nameRequired`. Success shows the toast `renamed`.
- Remove: opens a `ConfirmationModal` (slug `passkeys-remove-<id>`) with heading `removeTitle` (`{{name}}`). The body is `removeKeepsOthers`, or `removeLast` when it is the only passkey, then a `CheckboxInput` labelled `alsoSignOut` with `alsoSignOutHint` under it. The checkbox is **ticked by default when `lastUsedAt` is within the last 24 hours** (review M6). Confirm posts `{ id, signOutOtherSessions }` to `delete`; success shows the toast `removed` and reloads; failure shows `removeFailed`.

Add button (`addPasskey`, busy label `adding`): runs `registerFlow` with `askPassword` from `usePasswordPrompt('passkeys-password')` and `onReauthenticated: (body) => setUser(body)`. Success shows the toast `added` and reloads. A failure shows its message key inline (`role="alert"`) except `addCancelled`, which shows nothing.

All strings come from `usePasskeysT`. Toasts use `toast` from `@payloadcms/ui`. Buttons are `@payloadcms/ui` `Button` with `buttonStyle="secondary"` and `size="small"` in rows.

Add `retry: 'Try again'` to `en.ts` in this task.

**Step 6: Export.** `src/exports/client.ts` also exports `PasskeysManager`.

**Step 7: Generate and check.**

```bash
pnpm dev:generate-importmap
pnpm dev:generate-types
pnpm test:unit test/unit/managerField.spec.ts test/unit/clientBoundary.spec.ts test/unit/translations.spec.ts
pnpm typecheck
```

Expected: all pass. In `pnpm dev`, the account page shows the Passkeys section; another user's edit view does not; adding, renaming and removing work with Chrome's DevTools WebAuthn panel (virtual authenticator).

**Step 8: Commit.**

```bash
git add src dev/app dev/payload-types.ts test/unit/managerField.spec.ts
git commit -m "feat: add the Passkeys section to the account page"
```

### Task 29: `PasskeysProvider` and the enrolment prompt

**Files:**
- Create: `src/components/PasskeysProvider/index.tsx`, `src/components/PasskeysProvider/EnrolmentPrompt.tsx`
- Modify: `src/exports/client.ts`, `src/index.ts`, `src/components/passkeys.css`
- Test: Task 36 (Playwright); `test/unit/enrolmentStorage.spec.ts` already covers the rules

**Specification.**

`PasskeysProvider` props: `{ children: React.ReactNode; collections: string[]; enrolmentPrompt: boolean }`. It renders `children` and, after them, `<EnrolmentPrompt />` when all of these hold:
1. `enrolmentPrompt` is true.
2. `useAuth().user` exists and `user.collection` is in `collections`.
3. `shouldOfferEnrolment({ collection, local: localStorage, now: new Date(), session: sessionStorage, userId })` is true. That is the first admin page view of the browser session, and no "Not now" or "Don't ask again" applies. A user with no passkeys who reaches a signed-in admin page in a new browser session has just signed in with the password.
4. `await platformAuthenticatorIsAvailable()` is true.
5. `POST status` says `available` and `passkeys.length === 0`.

Checks 4 and 5 run only after 1 to 3 pass, so a normal page view makes no request.

`EnrolmentPrompt` is a non-modal card fixed bottom-right (bottom-centre under 768px), `role="dialog"` and `aria-labelledby` its title. Focus is not stolen. It contains:
- the title `enrolTitle` and the body `enrolBody`;
- the primary button `enrolAdd`, which runs `registerFlow`, as the manager does, with the same password prompt. On success it shows the toast `added`, hides the card, and calls `router.refresh()` so an open account page reloads its list;
- the secondary button `notNow`: `rememberChoice(…, 'not-now')`, then hide;
- the text button `dontAskAgain`: `rememberChoice(…, 'never')`, then hide;
- Esc does the same as Not now.

The provider never renders on the login page in practice: there is no user there.

Registration in `src/index.ts`, when `enabled`: append to `admin.components.providers`:

```ts
{ clientProps: { collections: resolved.collections, enrolmentPrompt: resolved.enrolmentPrompt }, path: '@the-digital-stride/payload-passkeys/client#PasskeysProvider' }
```

**Steps.**
1. Write both components to the specification.
2. Export `PasskeysProvider` from `src/exports/client.ts`.
3. Register it in `src/index.ts`.
4. Run `pnpm dev:generate-importmap && pnpm test:unit && pnpm typecheck`. Expected: PASS.
5. Check by hand in `pnpm dev`: sign in with the password as a user with no passkey and the card appears. "Not now" hides it; it stays hidden after reload and after signing out and in again (until 30 days pass).
6. Commit.

```bash
git add src dev/app
git commit -m "feat: offer a passkey after a password sign-in"
```

### Task 30: M3 gate: import map, types and the client graph

**Files:**
- Modify: none, unless a check fails

**Step 1: Regenerate and run everything.**

```bash
pnpm dev:generate-importmap && pnpm dev:generate-types
git diff --exit-code dev/app dev/payload-types.ts
pnpm lint && pnpm typecheck && pnpm test:unit && pnpm test:int
pnpm build && ls dist/exports
```

Expected:
- No diff, because the generated files are already committed.
- Every check passes.
- `dist/exports/client.js` and `dist/exports/rsc.js` exist.

**Step 2: Inspect the built client graph.** Run `node -e "import('./dist/exports/client.js').then(m => console.log(Object.keys(m)))"`. Expected: `[ 'PasskeysManager', 'PasskeysProvider', 'SignInWithPasskey' ]`, with no error about a server-only module. (The import may fail on CSS in plain Node; if so, check the list with `grep -o "export {[^}]*}" dist/exports/client.js` instead.)

**Step 3: Commit only if something was regenerated.**

```bash
git add dev/app dev/payload-types.ts
git commit -m "chore: regenerate the import map and types"
```

## Milestone M4: tests across adapters, and end to end

End state: every rejection path in design §9 has a test, and those tests pass on MongoDB, SQLite and Postgres. The multi-collection and concurrency findings (H3, M3) are proved. No response leaks a secret. A Playwright suite drives the real admin with a virtual authenticator. The published package's exports resolve.

### Task 31: The rejection matrix

**Files:**
- Test: `test/int/rejections.int.spec.ts`

**Step 1: Write the test, complete.** Each row runs one ceremony with one thing wrong and expects the generic failure and no new session.

```ts
// test/int/rejections.int.spec.ts
import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import type { TestClient } from '../helpers/api.js'
import type { CeremonyOverrides, SoftAuthenticator } from '../helpers/softAuthenticator.js'

import config from '../configs/multi.js'
import { cloneWithCookies, createClient, SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey } from '../helpers/ceremonies.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const enrol = async (collection: 'customers' | 'users' = 'users') => {
  const user = await createUser(payload, collection)
  const authenticator = createSoftAuthenticator({ origin: SERVER_URL })
  const { verify } = await registerPasskey(await passwordClient(config, collection, user.email), authenticator, { collection })
  expect(verify!.status).toBe(200)
  return { authenticator, user }
}

const sessionCount = async (collection: string, id: number | string) => ((await rawUser(payload, collection, id)).sessions ?? []).length

type SignInCase = {
  name: string
  /** Changes the ceremony: overrides for the authenticator, or a custom run. */
  overrides?: CeremonyOverrides & { credentialId?: string }
  run?: (ctx: { authenticator: SoftAuthenticator; client: TestClient; options: Record<string, unknown> }) => Promise<{ json: unknown; status: number }>
  setUp?: (ctx: { authenticator: SoftAuthenticator; user: { id: number | string } }) => Promise<void>
}

const OPTIONS = '/api/users/passkeys/sign-in/options'
const VERIFY = '/api/users/passkeys/sign-in/verify'

const signInCases: SignInCase[] = [
  { name: 'user verification missing', overrides: { userVerified: false } },
  { name: 'user presence missing', overrides: { userPresent: false } },
  { name: 'bad signature', overrides: { badSignature: true } },
  { name: 'wrong origin in clientDataJSON', overrides: { origin: 'https://evil.test' } },
  { name: 'wrong RP ID hash', overrides: { rpID: 'evil.test' } },
  { name: 'wrong ceremony type', overrides: { type: 'webauthn.create' } },
  { name: 'challenge the server never issued', overrides: { challenge: 'B'.repeat(43) } },
  { name: 'no userHandle', overrides: { userHandle: null } },
  {
    name: 'replayed assertion',
    run: async ({ authenticator, client, options }) => {
      const response = await authenticator.authenticate(options as never)
      const first = await client.post(VERIFY, { response })
      expect(first.status).toBe(200)
      return client.post(VERIFY, { response })
    },
  },
  {
    name: 'expired challenge',
    run: async ({ authenticator, client, options }) => {
      await payload.db.updateOne({ collection: 'passkey-challenges', data: { expiresAt: new Date(Date.now() - 1).toISOString() }, returning: false, where: { challenge: { equals: (options as { challenge: string }).challenge } } })
      return client.post(VERIFY, { response: await authenticator.authenticate(options as never) })
    },
  },
  {
    name: 'another browser (login CSRF)',
    run: async ({ authenticator, options }) =>
      createClient(config).post(VERIFY, { response: await authenticator.authenticate(options as never) }),
  },
  {
    name: 'registration challenge used for sign-in',
    run: async ({ authenticator, client }) => {
      const user = await createUser(payload, 'users')
      const owner = await passwordClient(config, 'users', user.email)
      const reg = await owner.post('/api/users/passkeys/register/options')
      const both = cloneWithCookies(config, new Map([...client.cookies, ...owner.cookies]))
      return both.post(VERIFY, { response: await authenticator.authenticate({ challenge: reg.json.options.challenge, rpId: 'localhost' } as never) })
    },
  },
  {
    name: 'deleted credential',
    setUp: async ({ authenticator }) => {
      await payload.db.deleteMany({ collection: 'passkeys', where: { credentialId: { equals: authenticator.credentialIds()[0] } } })
    },
  },
  {
    name: 'malformed response',
    run: async ({ client }) => client.post(VERIFY, { response: { id: 'x', rawId: 'y', response: {}, type: 'public-key' } }),
  },
  {
    name: 'unverified user (customers)',
    run: async ({ client }) => {
      const { authenticator, user } = await enrol('customers')
      await payload.db.updateOne({ collection: 'customers', data: { _verified: false }, id: user.id, returning: false })
      const options = await client.post('/api/customers/passkeys/sign-in/options')
      return client.post('/api/customers/passkeys/sign-in/verify', { response: await authenticator.authenticate(options.json.options) })
    },
  },
]

describe.each(signInCases)('sign-in refuses: $name', ({ name, overrides, run, setUp }) => {
  it('with the generic failure and no new session', async () => {
    const { authenticator, user } = await enrol()
    await setUp?.({ authenticator, user })
    const before = await sessionCount('users', user.id)
    const client = createClient(config)
    const options = (await client.post(OPTIONS)).json.options
    const result = run
      ? await run({ authenticator, client, options })
      : await client.post(VERIFY, { response: await authenticator.authenticate(options, overrides) })
    expect(result.status).toBe(400)
    expect((result.json as { error: string }).error).toBe('sign_in_failed')
    // The replay case's first verify signs in legitimately; the second must not.
    const replay = name === 'replayed assertion'
    expect(await sessionCount('users', user.id)).toBe(before + (replay ? 1 : 0))
    if (!replay) expect(client.cookies.has('payload-token')).toBe(false)
  })
})

const registrationCases: { name: string; overrides: CeremonyOverrides }[] = [
  { name: 'user verification missing', overrides: { userVerified: false } },
  { name: 'wrong origin', overrides: { origin: 'https://evil.test' } },
  { name: 'wrong RP ID', overrides: { rpID: 'evil.test' } },
  { name: 'wrong type', overrides: { type: 'webauthn.get' } },
  { name: 'not discoverable', overrides: { credPropsRk: false } },
  { name: 'unknown challenge', overrides: { challenge: 'C'.repeat(43) } },
]

describe.each(registrationCases)('registration refuses: $name', ({ overrides }) => {
  it('and stores nothing', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    const { verify } = await registerPasskey(client, createSoftAuthenticator({ origin: SERVER_URL }), { overrides })
    expect(verify!.json).toEqual({ error: 'registration_failed' })
    expect((await payload.count({ collection: 'passkeys', where: { 'user.value': { equals: user.id } } })).totalDocs).toBe(0)
  })
})

describe('registration refuses another user\'s challenge', () => {
  it('even with that user\'s browser key', async () => {
    const alice = await createUser(payload, 'users')
    const bob = await createUser(payload, 'users')
    const aliceClient = await passwordClient(config, 'users', alice.email)
    const bobClient = await passwordClient(config, 'users', bob.email)
    const options = await aliceClient.post('/api/users/passkeys/register/options')
    const response = await createSoftAuthenticator({ origin: SERVER_URL }).register(options.json.options)
    bobClient.cookies.set('payload-passkeys-reg-users', aliceClient.cookies.get('payload-passkeys-reg-users')!)
    expect((await bobClient.post('/api/users/passkeys/register/verify', { response })).json).toEqual({ error: 'registration_failed' })
  })
})
```

**Step 2: Run it on all three adapters.**

```bash
pnpm test:int test/int/rejections.int.spec.ts
DATABASE_ADAPTER=sqlite pnpm test:int test/int/rejections.int.spec.ts
DATABASE_ADAPTER=postgres pnpm test:int test/int/rejections.int.spec.ts
```

Expected: PASS on each (22 tests). Any failure here is a security bug: fix the endpoint, never the expectation.

**Step 3: Commit.**

```bash
git add test/int/rejections.int.spec.ts
git commit -m "test: cover every registration and sign-in rejection path"
```

### Task 32: Multi-collection isolation with colliding IDs (review H3)

> **Implemented as (2026-11-06):** the test helpers' `collection` parameter is a slug and keeps its name; the field they write and query on the rows is `authCollection`.

**Files:**
- Test: `test/int/multiCollection.int.spec.ts`

**Step 1: Write the test, complete.**

```ts
// test/int/multiCollection.int.spec.ts
import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import config from '../configs/multi.js'
import { createClient, SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey, signInWithPasskey } from '../helpers/ceremonies.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser } from '../helpers/users.js'

const sql = (process.env.DATABASE_ADAPTER ?? 'mongo') !== 'mongo'
let payload: Payload
let user: { email: string; id: number | string }
let customer: { email: string; id: number | string }

beforeAll(async () => {
  payload = await getPayload({ config })
  // First row in each table on a fresh database: on SQL both are id 1.
  user = await createUser(payload, 'users')
  customer = await createUser(payload, 'customers')
})
afterAll(async () => {
  await payload.destroy()
})

describe('two auth collections (review H3)', () => {
  it.runIf(sql)('really do share an ID on SQL', () => {
    expect(String(user.id)).toBe(String(customer.id))
  })

  it("a customer's passkey cannot sign in to users, even with the same ID", async () => {
    const authenticator = createSoftAuthenticator({ origin: SERVER_URL })
    await registerPasskey(await passwordClient(config, 'customers', customer.email), authenticator, { collection: 'customers' })
    const client = createClient(config)
    const { verify } = await signInWithPasskey(client, authenticator, { collection: 'users' })
    expect(verify!.json).toEqual({ error: 'sign_in_failed' })
    expect((await client.get('/api/users/me')).json.user).toBeNull()
    const ok = await signInWithPasskey(createClient(config), authenticator, { collection: 'customers' })
    expect(ok.verify!.status).toBe(200)
    expect(ok.verify!.json.user.collection).toBe('customers')
  })

  it("users with the same ID see, rename and remove only their own collection's passkeys", async () => {
    const asCustomer = await passwordClient(config, 'customers', customer.email)
    const customerPasskeys = (await asCustomer.post('/api/customers/passkeys/status')).json.passkeys
    expect(customerPasskeys.length).toBeGreaterThan(0)
    const asUser = await passwordClient(config, 'users', user.email)
    expect((await asUser.get('/api/passkeys?depth=0')).json.docs).toEqual([])
    expect((await asUser.post('/api/users/passkeys/status')).json.passkeys).toEqual([])
    const id = customerPasskeys[0].id
    expect((await asUser.post('/api/users/passkeys/rename', { id, name: 'Taken' })).status).toBe(404)
    expect((await asUser.post('/api/users/passkeys/delete', { id })).status).toBe(404)
  })

  it('a users session cannot call the customers endpoints', async () => {
    const asUser = await passwordClient(config, 'users', user.email)
    expect((await asUser.post('/api/customers/passkeys/register/options')).status).toBe(401)
  })
})
```

**Step 2: Run it.** Run it on Postgres first (the case H3 is about), then SQLite and MongoDB. Expected: PASS (4 tests on SQL; 3 on Mongo, with the ID check skipped).

**Step 3: Commit.**

```bash
git add test/int/multiCollection.int.spec.ts
git commit -m "test: prove passkeys stay in their own collection when IDs collide"
```

### Task 33: Parallel double-verify (review M3)

**Files:**
- Test: `test/int/concurrency.int.spec.ts`

**Step 1: Write the test, complete.**

```ts
// test/int/concurrency.int.spec.ts
import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import config from '../configs/single.js'
import { cloneWithCookies, createClient, SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey } from '../helpers/ceremonies.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, rawUser } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

describe('one challenge, many parallel verifies (review M3)', () => {
  it('signs in exactly once', async () => {
    const user = await createUser(payload, 'users')
    const authenticator = createSoftAuthenticator({ origin: SERVER_URL })
    await registerPasskey(await passwordClient(config, 'users', user.email), authenticator)
    const before = (await rawUser(payload, 'users', user.id)).sessions!.length

    for (let round = 0; round < 5; round++) {
      const client = createClient(config)
      const options = (await client.post('/api/users/passkeys/sign-in/options')).json.options
      const response = await authenticator.authenticate(options)
      const results = await Promise.all(
        Array.from({ length: 4 }, () => cloneWithCookies(config, client.cookies).post('/api/users/passkeys/sign-in/verify', { response })),
      )
      expect(results.filter((r) => r.status === 200)).toHaveLength(1)
    }
    expect((await rawUser(payload, 'users', user.id)).sessions!.length).toBe(before + 5)
  })

  it('registers exactly once', async () => {
    const user = await createUser(payload, 'users')
    const client = await passwordClient(config, 'users', user.email)
    const options = (await client.post('/api/users/passkeys/register/options')).json.options
    const response = await createSoftAuthenticator({ origin: SERVER_URL }).register(options)
    const results = await Promise.all(
      Array.from({ length: 4 }, () => cloneWithCookies(config, client.cookies).post('/api/users/passkeys/register/verify', { response })),
    )
    expect(results.filter((r) => r.status === 200)).toHaveLength(1)
    expect((await payload.count({ collection: 'passkeys', where: { user: { equals: user.id } } })).totalDocs).toBe(1)
  })
})
```

**Step 2: Run it on all three adapters, three times each.** Races are probabilistic, so repeat:

```bash
for a in mongo sqlite postgres; do for i in 1 2 3; do DATABASE_ADAPTER=$a pnpm test:int test/int/concurrency.int.spec.ts || echo "FAILED $a $i"; done; done
```

Expected: no `FAILED` lines. If SQLite reports `SQLITE_BUSY` rather than a unique-constraint error, that is still a refused insert (any insert error is a replay); the assertion of exactly one 200 is what matters.

**Step 3: Commit.**

```bash
git add test/int/concurrency.int.spec.ts
git commit -m "test: prove a challenge signs in at most once under parallel verifies"
```

### Task 34: No secrets in any response; every guard on every endpoint (review M1, M4, L2)

**Files:**
- Test: `test/int/guards.int.spec.ts`

**Step 1: Write the test, complete.**

```ts
// test/int/guards.int.spec.ts
import type { Payload } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { ENDPOINTS } from '../../src/shared/constants.js'
import config from '../configs/single.js'
import { createClient, SERVER_URL } from '../helpers/api.js'
import { passwordClient, registerPasskey, signInWithPasskey } from '../helpers/ceremonies.js'
import { findSecretKeys } from '../helpers/secrets.js'
import { createSoftAuthenticator } from '../helpers/softAuthenticator.js'
import { createUser, PASSWORD } from '../helpers/users.js'

let payload: Payload
beforeAll(async () => {
  payload = await getPayload({ config })
})
afterAll(async () => {
  await payload.destroy()
})

const all = Object.values(ENDPOINTS)
const signedIn = [ENDPOINTS.registerOptions, ENDPOINTS.registerVerify, ENDPOINTS.reauth, ENDPOINTS.rename, ENDPOINTS.delete]
const path = (endpoint: string) => `/api/users${endpoint}`

describe('no plugin response contains a secret (review M1)', () => {
  it('across a full lifecycle', async () => {
    const user = await createUser(payload, 'users', { apiKey: crypto.randomUUID(), enableAPIKey: true })
    const client = await passwordClient(config, 'users', user.email)
    const authenticator = createSoftAuthenticator({ origin: SERVER_URL })
    const seen: unknown[] = []
    const { options, verify } = await registerPasskey(client, authenticator)
    seen.push(options.json, verify!.json)
    const signIn = await signInWithPasskey(createClient(config), authenticator)
    seen.push(signIn.options.json, signIn.verify!.json)
    seen.push((await client.post(path(ENDPOINTS.status))).json)
    seen.push((await client.post(path(ENDPOINTS.reauth), { password: PASSWORD })).json)
    const id = verify!.json.passkey.id
    seen.push((await client.post(path(ENDPOINTS.rename), { id, name: 'Renamed' })).json)
    seen.push((await client.post(path(ENDPOINTS.delete), { id })).json)
    for (const body of seen) expect(findSecretKeys(body)).toEqual([])
    expect(JSON.stringify(seen)).not.toMatch(/"(hash|salt)"/)
  })
})

describe('content type (review M4)', () => {
  it.each(all)('%s refuses multipart with a _payload field', async (endpoint) => {
    const res = await createClient(config).post(path(endpoint), '--x\r\nContent-Disposition: form-data; name="_payload"\r\n\r\n{}\r\n--x--', {
      contentType: 'multipart/form-data; boundary=x',
    })
    expect(res.status).toBe(415)
  })
  it.each(all)('%s refuses text/plain', async (endpoint) => {
    expect((await createClient(config).post(path(endpoint), '{}', { contentType: 'text/plain' })).status).toBe(415)
  })
})

describe('origin (review M4)', () => {
  it.each(all.filter((e) => e !== ENDPOINTS.status))('%s refuses a foreign Origin', async (endpoint) => {
    expect((await createClient(config, { origin: 'https://evil.test' }).post(path(endpoint))).status).toBe(403)
  })
  it('status answers any origin, saying passkeys are unavailable there', async () => {
    const res = await createClient(config, { origin: 'https://evil.test' }).post(path(ENDPOINTS.status))
    expect(res.json).toEqual({ available: false })
  })
})

describe('session kind (review L2)', () => {
  it.each(signedIn)('%s refuses an API key and a header JWT', async (endpoint) => {
    const apiKey = crypto.randomUUID()
    const user = await createUser(payload, 'users', { apiKey, enableAPIKey: true })
    expect((await createClient(config).post(path(endpoint), {}, { headers: { Authorization: `users API-Key ${apiKey}` } })).status).toBe(403)
    const login = await createClient(config).post('/api/users/login', { email: user.email, password: PASSWORD })
    expect((await createClient(config).post(path(endpoint), {}, { headers: { Authorization: `JWT ${login.json.token}` } })).status).toBe(403)
  })
})

describe('rate limiting', () => {
  it('a hook that throws refuses with 429 (fail closed)', async () => {
    const { buildDevConfig } = await import('../../dev/buildConfig.js')
    const throwing = await buildDevConfig({ plugin: { rateLimit: () => { throw new Error('limiter down') } }, variant: 'single' })
    const res = await createClient(throwing).post(path(ENDPOINTS.signInOptions))
    expect(res.status).toBe(429)
  })
})
```

The rate-limit case builds a second config against the same database. If two Payload instances on one connection misbehave on an adapter, move that case into its own file with its own `test/configs/throwingRateLimit.ts`.

**Step 2: Run it on all three adapters.** Expected: PASS.

**Step 3: Commit.**

```bash
git add test/int/guards.int.spec.ts
git commit -m "test: assert no secrets leak and every endpoint enforces its guards"
```

### Task 35: SQL migrations generate cleanly

**Files:**
- Create: `dev/migrations/postgres/*`, `dev/migrations/sqlite/*` (generated), `scripts/check-migrations.sh`

**Step 1: Generate the example migrations.**

```bash
docker compose -f dev/docker-compose.yml up -d postgres
DATABASE_ADAPTER=postgres PAYLOAD_MIGRATING=true pnpm dev:payload migrate:create initial
DATABASE_ADAPTER=sqlite DATABASE_URL=file:./test/.tmp/migrate.db PAYLOAD_MIGRATING=true pnpm dev:payload migrate:create initial
```

Expected: each folder gains `<timestamp>_initial.ts` and `.json`, creating `passkeys`, `passkey_challenges`, `passkey_challenge_uses`, and the `passkey_user_handle` column on `users`. Read both files. The unique indexes on `credential_id` and `challenge` must be present; if not, stop, because the replay guard would be missing on that adapter.

**Step 2: Write `scripts/check-migrations.sh`.** It applies the committed migrations to an empty database, then asks for a new one with `--skip-empty`. Any file created means the schema drifted from the committed migrations.

```bash
#!/usr/bin/env bash
set -euo pipefail
adapter="$1" # postgres | sqlite
export DATABASE_ADAPTER="$adapter" PAYLOAD_MIGRATING=true NODE_ENV=production
if [ "$adapter" = sqlite ]; then export DATABASE_URL="file:$(pwd)/test/.tmp/check-migrations.db"; rm -f test/.tmp/check-migrations.db; mkdir -p test/.tmp; fi
pnpm dev:payload migrate:fresh --force-accept-warning
pnpm dev:payload migrate:create drift-check --skip-empty
if [ -n "$(git status --porcelain "dev/migrations/$adapter")" ]; then
  echo "The plugin's schema changed: regenerate dev/migrations/$adapter and add a README upgrade note." >&2
  git status --porcelain "dev/migrations/$adapter" >&2
  exit 1
fi
echo "Migrations for $adapter are up to date."
```

**Step 3: Run it.** Run `bash scripts/check-migrations.sh postgres && bash scripts/check-migrations.sh sqlite`. Expected: "Migrations for postgres are up to date." and the same for sqlite.

**Step 4: Commit.**

```bash
chmod +x scripts/check-migrations.sh
git add dev/migrations scripts/check-migrations.sh
git commit -m "test: ship example SQL migrations and a drift check"
```

### Task 36: Playwright end to end with a CDP virtual authenticator

**Files:**
- Create: `playwright.config.ts`, `test/e2e/helpers.ts`, `test/e2e/passkeys.e2e.spec.ts`

**Step 1: Write `playwright.config.ts`.** The dev server runs on SQLite with a throwaway file, so e2e needs no database service. One worker, because the specs share that database.

```ts
import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  forbidOnly: !!process.env.CI,
  fullyParallel: false,
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : 'list',
  retries: process.env.CI ? 1 : 0,
  testDir: 'test/e2e',
  use: { baseURL: 'http://localhost:3000', trace: 'retain-on-failure' },
  webServer: {
    command: 'pnpm dev',
    env: {
      DATABASE_ADAPTER: 'sqlite',
      DATABASE_URL: 'file:./test/.tmp/e2e.db',
      PAYLOAD_DROP_DATABASE: 'true',
      PAYLOAD_SECRET: 'e2e-secret-not-for-production',
    },
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
    url: 'http://localhost:3000/admin/login',
  },
  workers: 1,
})
```

**Step 2: Write `test/e2e/helpers.ts`, complete.**

```ts
import type { CDPSession, Page } from '@playwright/test'

import { expect } from '@playwright/test'

export const DEV_USER = { email: 'dev@payloadcms.com', password: 'test' }

/** A platform authenticator with UV, as Touch ID or Windows Hello would be (Verified facts Q6). */
export const addVirtualAuthenticator = async (page: Page): Promise<{ authenticatorId: string; cdp: CDPSession }> => {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      automaticPresenceSimulation: true,
      defaultBackupEligibility: true,
      defaultBackupState: true,
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      protocol: 'ctap2',
      transport: 'internal',
    },
  })
  return { authenticatorId, cdp }
}

export const credentialsOf = async (cdp: CDPSession, authenticatorId: string) =>
  (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials

export const passwordSignIn = async (page: Page, origin = 'http://localhost:3000', path = '/admin/login') => {
  await page.goto(`${origin}${path}`)
  await page.getByLabel('Email').fill(DEV_USER.email)
  await page.getByLabel('Password').fill(DEV_USER.password)
  await page.getByRole('button', { name: 'Login' }).click()
  await expect(page).not.toHaveURL(/\/login/)
}

export const signOut = async (page: Page, origin = 'http://localhost:3000') => {
  await page.goto(`${origin}/admin/logout`)
  await expect(page).toHaveURL(/\/admin\/login/)
}
```

**Step 3: Write `test/e2e/passkeys.e2e.spec.ts`.** Run the cases in order (`test.describe.configure({ mode: 'serial' })`), sharing one page so the virtual authenticator keeps its credential.

1. **Enrol from the prompt.** Password sign-in, then expect the dialog named "Sign in faster with a passkey". Press "Add a passkey". Expect the toast "Passkey added." and `credentialsOf(...)` to have length 1 with `isResidentCredential: true`.
2. **The prompt does not come back** in the same browser session (reload the dashboard: no dialog).
3. **Sign in with the button.** Sign out, then on `/admin/login` press "Sign in with a passkey". Expect `/admin` (the dashboard), and the account menu to show the dev user.
4. **Redirects are kept to the admin.** Sign out, then go to `/admin/login?redirect=%2Fadmin%2Fcollections%2Fusers` and sign in with the button: expect `/admin/collections/users`. Sign out, then try `/admin/login?redirect=https%3A%2F%2Fevil.test`: expect `/admin`.
5. **Rename.** On `/admin/account`, press Rename, type "Work laptop", press Enter. Expect the toast "Passkey renamed." and the row to read "Work laptop" after reload.
6. **Remove, with sign-out everywhere.**
   - Open a second browser context and sign in there with the password.
   - In the first context, press Remove. Expect the heading "Remove “Work laptop”?", the text "This is your only passkey. You can still sign in with your password." and the box "Also sign out everywhere else" **ticked** (used within 24 hours).
   - Confirm. Expect the toast "Passkey removed.", the second context's next navigation to land on `/admin/login`, and the first context still signed in.
7. **A failed ceremony shows the generic message.** Add a passkey again (the password prompt may appear: fill `test`). Sign out. Run `WebAuthn.setResponseOverrideBits({ authenticatorId, isBadUV: true })` and press the button. Expect "That passkey couldn’t be used. Try again or sign in with your password." with `role=alert`, and the URL still `/admin/login`. Reset the bits.
8. **Preview host.** Open `http://127.0.0.1:3000/admin/login`: no "Sign in with a passkey" button, and the note "Passkey sign-in isn’t available at this address. Sign in with your password." Sign in with the password there (the dev config lists `127.0.0.1:3000` in `csrf`). On `/admin/account`, expect "Passkeys work on localhost only." and no "Add a passkey" button.
9. **The fresh-session rule asks for the password.** Back on localhost, signed in, call the dev-only endpoint below to age the session, then press "Add a passkey". Expect the dialog "Confirm your password". A wrong password shows "That password didn’t work."; the right one goes on to add the passkey.

For case 9, add a dev-only endpoint to `dev/buildConfig.ts` (never in `src/`): `POST /api/users/test/age-session`, enabled only when `process.env.PAYLOAD_E2E === 'true'`, which moves the caller's session `createdAt` back 30 minutes. Set `PAYLOAD_E2E: 'true'` in the Playwright `webServer.env`.

Write each case with role-based locators (`getByRole('button', { name: 'Sign in with a passkey' })`, `getByRole('dialog', { name: … })`, `getByRole('alert')`), never CSS classes. Use the visible UK English copy from `en.ts`: the tests double as a copy check. In code, write the curly apostrophes (’) exactly as they appear in `en.ts`.

**Step 4: Run it.** Run `pnpm test:e2e`. Expected: 9 passed.

**Step 5: Commit.**

```bash
git add playwright.config.ts test/e2e dev/buildConfig.ts
git commit -m "test: drive the admin end to end with a virtual authenticator"
```

### Task 37: The published package resolves

**Files:**
- Modify: `package.json` (dev dependencies `publint@0.3.25`, `@arethetypeswrong/cli@0.18.5`; script `check:package`)
- Create: `scripts/check-package.mjs`

**Step 1: Write `scripts/check-package.mjs`, complete.** It packs the package as npm would publish it and checks what is inside.

```js
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

const dir = mkdtempSync(path.join(tmpdir(), 'payload-passkeys-pack-'))
try {
  execFileSync('pnpm', ['pack', '--pack-destination', dir], { stdio: 'inherit' })
  const tarball = execFileSync('ls', [dir]).toString().trim()
  execFileSync('tar', ['-xzf', path.join(dir, tarball), '-C', dir])
  const root = path.join(dir, 'package')
  const manifest = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'))
  const files = execFileSync('find', ['.', '-type', 'f'], { cwd: root }).toString().split('\n').filter(Boolean)

  const problems = []
  for (const [entry, target] of Object.entries(manifest.exports)) {
    for (const file of [target.import, target.types]) {
      if (!files.includes(`./${file.replace(/^\.\//, '')}`)) problems.push(`${entry} points at missing ${file}`)
    }
  }
  for (const file of files) {
    if (/^\.\/(src|test|dev|scripts|\.github)\//.test(file)) problems.push(`unexpected file ${file}`)
    if (/\.(spec|test)\.[jt]s$/.test(file)) problems.push(`test file ${file}`)
  }
  if (!files.includes('./dist/bin/reset.js')) problems.push('the passkeys:reset script is missing')
  if (!files.some((f) => f.endsWith('.css'))) problems.push('passkeys.css is missing')
  if (manifest.dependencies['@simplewebauthn/server'] !== '14.0.3') problems.push('SimpleWebAuthn is not pinned exactly')
  if (problems.length) {
    console.error(problems.join('\n'))
    process.exit(1)
  }
  console.log(`Package OK: ${files.length} files, exports ${Object.keys(manifest.exports).join(', ')}`)
} finally {
  rmSync(dir, { force: true, recursive: true })
}
```

Add the script `"check:package": "pnpm build && node scripts/check-package.mjs && publint && attw --pack . --profile esm-only"`.

**Step 2: Run it.** Run `pnpm check:package`. Expected: "Package OK: …"; publint reports no errors; attw reports no problems for the `esm-only` profile.

**Step 3: Commit.**

```bash
git add package.json pnpm-lock.yaml scripts/check-package.mjs
git commit -m "test: check the packed package's exports, files and pins"
```

## Milestone M5: docs, CI and release

End state: a stranger can install the plugin from the README alone. CI runs the matrix of Payload minors × adapters on every pull request, plus a nightly run against `latest` and `beta`. Releases go out through Changesets and npm trusted publishing with provenance, from a protected workflow with SHA-pinned actions.

### Task 38: README

> **Implemented as (2026-11-06):** Changesets was set up separately (`chore: set up Changesets`), so this task wrote only the README. The samples live in `dev/readme-samples.ts` with stubs in `dev/readme-samples.d.ts` (referenced with a triple-slash directive, because tsc skips a `.d.ts` that shares its name with an included `.ts`), and `test/unit/readmeSamples.spec.ts` fails if a README code block differs from them. Item 8 is corrected in the README: `onSignIn` runs after `beforeLogin` and before `afterLogin`, and a passkey sign-in clears the lockout, not only the attempt count.

**Files:**
- Create: `README.md`, `.changeset/config.json`, `.changeset/README.md`

**Step 1: Write `README.md` with these sections, in this order.** UK English throughout. Every code sample must be copied from a file that a test or the dev app exercises, never typed fresh.

1. **What it does.** One paragraph: passkeys alongside email and password; the password always keeps working; sessions are ordinary Payload sessions.
2. **Requirements.** Payload `>=3.90 <4`, Next 15.4.8+ or 16, React 19, Node 22.12+, an auth collection with sessions on (the default), served over HTTPS or on `localhost`.
3. **Install.**
   ```bash
   pnpm add @the-digital-stride/payload-passkeys
   ```
   Then add `passkeysPlugin()` to `plugins`. Show the minimal config, then the full option table: every key in `PasskeysPluginOptions`, with type, default and one line each.
4. **After installing: generate, and migrate on SQL.**
   - Everyone: `pnpm payload generate:importmap` and `pnpm payload generate:types`.
   - Postgres and SQLite: `pnpm payload migrate:create passkeys` then `pnpm payload migrate`. The plugin adds three collections and a field; `enabled: false` keeps them, so turning it off never needs a migration.
   - MongoDB: nothing. On MongoDB the plugin builds its own unique indexes at boot; the database user needs `createIndex`.
5. **Domains, RP ID and preview deployments.**
   - What the RP ID is, and that it can never be a hosting suffix like `vercel.app`.
   - Origins must be the RP ID or under it.
   - Preview deployments on `*.vercel.app` show password sign-in only, with the note. To test passkeys on previews, give them a custom domain under the production domain (for example `preview.example.com`) and add that origin.
   - Changing `rpID` later breaks existing passkeys unless the new value is a parent domain.
   - Passkeys made on `localhost` work only there; if local development shares the production database, they show as "Made for localhost".
6. **CSRF.** If `serverURL` is not set, set `csrf` to every origin the admin is served from, including preview URLs (`VERCEL_URL`, `VERCEL_BRANCH_URL`), or Payload accepts the session cookie from any site. The plugin warns at boot, and refuses to start with `sameSite: 'None'` and no `csrf`.
7. **Rate limiting.** Payload has no IP rate limiter, and serverless instances share no memory, so pass `rateLimit`. Explain the arguments (`action`, `key`, `ip`, `userId`). Explain that the IP comes from `x-real-ip` or `x-forwarded-for` and is trustworthy only behind a proxy that sets those headers itself. Give two examples:
   - **Vercel WAF** (`@vercel/firewall` 1.2.6: `checkRateLimit(rateLimitId, { headers, rateLimitKey })` returns `{ rateLimited, error? }`):
     ```ts
     import { checkRateLimit } from '@vercel/firewall'

     rateLimit: async ({ key, req }) => {
       if (process.env.VERCEL !== '1') return true
       const { rateLimited } = await checkRateLimit('passkeys', { headers: req.headers, rateLimitKey: key })
       return !rateLimited
     },
     ```
     with the dashboard steps to create a rate-limit rule whose ID is `passkeys`.
   - **Upstash** (`@upstash/ratelimit` 2.2.0):
     ```ts
     import { Ratelimit } from '@upstash/ratelimit'
     import { Redis } from '@upstash/redis'

     const limiter = new Ratelimit({ limiter: Ratelimit.slidingWindow(10, '1 m'), prefix: 'passkeys', redis: Redis.fromEnv() })

     rateLimit: async ({ action, key }) => (await limiter.limit(`${action}:${key}`)).success,
     ```
   The hook fails closed: a throw refuses the request with 429.
8. **What a passkey sign-in does and doesn't run.**
   - It runs the collection's `beforeLogin` and `afterLogin` hooks, Payload's verification check and session handling.
   - It does **not** run `beforeOperation`/`afterOperation` for `login` (review L8). Use `onSignIn` instead, and show an audit-log example.
   - A password lockout does not block a passkey (design D15); the event `passkeys.signed_in_while_locked` is logged and the attempts are reset.
9. **Recovery.** Run `pnpm payload passkeys:reset --collection users --email you@example.com`. It removes that user's passkeys and signs them out everywhere; the password and forgot-password still work.
10. **Logging and privacy.**
    - The event list.
    - IPs appear only on failures, truncated by default (`logging.ip`).
    - Under UK GDPR an IP address is personal data. The lawful basis is legitimate interest in security, and retention is your log retention.
11. **Security model.** A short summary of design §6, and a link to `SECURITY.md`.
12. **Translations.** The `passkeys` namespace, and how to override a string or add a language through `i18n.translations`.
13. **Verifying this package.** `npm audit signatures`, and how to read the provenance on npmjs.com.
14. **Compatibility and support.** The tested Payload minors and adapters (from the CI matrix), and the v4 plan.

**Step 2: Set up Changesets.**

```bash
pnpm changeset init
```

Set `.changeset/config.json` to `{ "$schema": "https://unpkg.com/@changesets/config@3.1.1/schema.json", "access": "public", "baseBranch": "main", "changelog": ["@changesets/changelog-github", { "repo": "The-Digital-Stride/payload-passkeys" }], "commit": false, "updateInternalDependencies": "patch" }`. Add `@changesets/changelog-github@1.0.1` as an exact dev dependency.

**Step 3: Check the samples.** Run `pnpm typecheck` with each README snippet pasted into `dev/readme-samples.ts` (kept, and type-checked in CI so the README can't rot). Expected: no errors. (Stub `@vercel/firewall` and `@upstash/*` with `declare module` in `dev/readme-samples.d.ts` instead of installing them.)

**Step 4: Commit.**

```bash
git add README.md .changeset package.json pnpm-lock.yaml dev/readme-samples.ts dev/readme-samples.d.ts
git commit -m "docs: add the README and Changesets"
```

### Task 39: SECURITY.md and CODEOWNERS (review L9)

**Files:**
- Create: `SECURITY.md`, `.github/CODEOWNERS`

**Step 1: Write `SECURITY.md`.**
- **Supported versions:** a table with the latest minor of the current major supported, and everything else unsupported.
- **Reporting:** use GitHub private vulnerability reporting (the "Report a vulnerability" button on the Security tab). Never open a public issue, and never email exploit details.
- **What to expect:** acknowledgement within 3 working days and a first assessment within 10. We fix before disclosure, agree a disclosure date with the reporter, credit them unless they ask otherwise, and publish a GitHub Security Advisory with a CVE where one applies.
- **In scope:** the plugin's endpoints, session minting, challenge handling, the admin components and the release pipeline.
- **Out of scope:** Payload itself (report to Payload), browsers and authenticators, and hosts that ignore the README's CSRF or rate-limiting guidance.
- **Verifying releases:** provenance and `npm audit signatures`.

**Step 2: Write `.github/CODEOWNERS`.**

```
# Changes to CI, release and security-critical code need a maintainer's review.
/.github/                      <maintainer-handle>
/src/server/mintSession.ts     <maintainer-handle>
/src/server/challenges.ts      <maintainer-handle>
/src/server/endpoints/         <maintainer-handle>
/package.json                  <maintainer-handle>
/pnpm-workspace.yaml           <maintainer-handle>
```

Replace `<maintainer-handle>` with the real GitHub user or team in Task 44. Don't guess a handle.

**Step 3: Commit.**

```bash
git add SECURITY.md .github/CODEOWNERS
git commit -m "docs: add the security policy and code owners"
```

### Task 40: CI workflow (lint, types, unit, the integration matrix, migrations, e2e)

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/actions/setup/action.yml`

**Step 1: Write the composite setup action, complete.** It is a local action in the same repo, so it needs no pin.

```yaml
# .github/actions/setup/action.yml
name: Set up
description: pnpm, Node and a frozen install
inputs:
  node-version:
    default: '22'
    description: Node version
runs:
  using: composite
  steps:
    - uses: pnpm/action-setup@73e46992e05b19abd31f2f3c20e0e7370d762115 # v6.1.1
    - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
      with:
        cache: pnpm
        node-version: ${{ inputs.node-version }}
    - run: pnpm install --frozen-lockfile
      shell: bash
```

**Step 2: Write `.github/workflows/ci.yml`, complete.**

```yaml
name: CI

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

concurrency:
  cancel-in-progress: true
  group: ci-${{ github.workflow }}-${{ github.ref }}

jobs:
  static:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: ./.github/actions/setup
      - name: Registry signatures
        run: npm audit signatures
      - run: pnpm lint
      - run: pnpm typecheck
      - run: pnpm test:unit
      - run: pnpm check:package
      - name: Generated files are committed
        run: |
          pnpm dev:generate-importmap
          pnpm dev:generate-types
          git diff --exit-code dev

  integration:
    needs: static
    runs-on: ubuntu-24.04
    strategy:
      fail-fast: false
      matrix:
        adapter: [mongo, sqlite, postgres]
        payload: ['3.90.2', '3.91.0', '3.92.1', '3.93.0']
        node: ['22']
        include:
          - adapter: mongo
            node: '24'
            payload: '3.93.0'
    services:
      postgres:
        image: postgres:17
        env:
          POSTGRES_DB: payload_passkeys
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd "pg_isready -U postgres" --health-interval 5s --health-timeout 5s --health-retries 10
        ports: ['5432:5432']
    env:
      DATABASE_ADAPTER: ${{ matrix.adapter }}
      DATABASE_URL: ${{ matrix.adapter == 'postgres' && 'postgres://postgres:postgres@127.0.0.1:5432/payload_passkeys' || '' }}
    name: int (payload ${{ matrix.payload }}, ${{ matrix.adapter }}, node ${{ matrix.node }})
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: ./.github/actions/setup
        with:
          node-version: ${{ matrix.node }}
      - name: Use Payload ${{ matrix.payload }}
        if: matrix.payload != '3.93.0'
        run: node scripts/use-payload-version.mjs ${{ matrix.payload }}
      - run: pnpm test:int

  migrations:
    needs: static
    runs-on: ubuntu-24.04
    services:
      postgres:
        image: postgres:17
        env:
          POSTGRES_DB: payload_passkeys
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd "pg_isready -U postgres" --health-interval 5s --health-timeout 5s --health-retries 10
        ports: ['5432:5432']
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: ./.github/actions/setup
      - run: bash scripts/check-migrations.sh postgres
        env:
          DATABASE_URL: postgres://postgres:postgres@127.0.0.1:5432/payload_passkeys
      - run: bash scripts/check-migrations.sh sqlite

  e2e:
    needs: static
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: ./.github/actions/setup
      - run: pnpm exec playwright install --with-deps chromium
      - run: pnpm test:e2e
      - if: failure()
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: playwright-report
          path: playwright-report
          retention-days: 14
```

`use-payload-version.mjs` changes the lockfile in the runner only, so `--frozen-lockfile` is not used after it. That is intended: the matrix tests what a host would install.

`npm audit signatures` was checked against a pnpm-installed tree in a scratch project on 2026-11-06 ("2 packages have verified registry signatures"). On the first CI run, compare its package count with `pnpm list --depth Infinity --json`. If it counts only the top-level packages, record that in Verified facts and keep the step anyway: it still covers the direct dependencies.

**Step 3: Push a branch and open a draft PR (the developer does this).** Expected: every job green. Then mark the `static`, `integration`, `migrations` and `e2e` checks as required (Task 44).

**Step 4: Commit.**

```bash
git add .github/workflows/ci.yml .github/actions/setup/action.yml
git commit -m "ci: run lint, types, unit, the integration matrix, migrations and e2e"
```

### Task 41: Nightly contract run against `latest` and `beta`

**Files:**
- Create: `.github/workflows/nightly.yml`

**Step 1: Write it, complete.**

```yaml
name: Nightly

on:
  schedule:
    - cron: '17 3 * * *'
  workflow_dispatch:

permissions:
  contents: read

jobs:
  contract:
    runs-on: ubuntu-24.04
    strategy:
      fail-fast: false
      matrix:
        adapter: [mongo, sqlite, postgres]
        payload: [latest, beta]
    continue-on-error: ${{ matrix.payload == 'beta' }}
    services:
      postgres:
        image: postgres:17
        env:
          POSTGRES_DB: payload_passkeys
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd "pg_isready -U postgres" --health-interval 5s --health-timeout 5s --health-retries 10
        ports: ['5432:5432']
    env:
      DATABASE_ADAPTER: ${{ matrix.adapter }}
      DATABASE_URL: ${{ matrix.adapter == 'postgres' && 'postgres://postgres:postgres@127.0.0.1:5432/payload_passkeys' || '' }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: ./.github/actions/setup
      - run: node scripts/use-payload-version.mjs ${{ matrix.payload }}
      - name: Contract first, then everything
        run: |
          pnpm test:int test/int/mintSession.contract.int.spec.ts test/int/reauthenticate.contract.int.spec.ts
          pnpm test:int

  report:
    needs: contract
    if: failure()
    permissions:
      issues: write
    runs-on: ubuntu-24.04
    steps:
      - name: Open or update the nightly issue
        env:
          GH_TOKEN: ${{ github.token }}
          RUN_URL: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
        run: |
          existing=$(gh issue list -R "$GITHUB_REPOSITORY" --label nightly --state open --json number --jq '.[0].number')
          if [ -n "$existing" ]; then gh issue comment "$existing" -R "$GITHUB_REPOSITORY" --body "Failed again: $RUN_URL"
          else gh issue create -R "$GITHUB_REPOSITORY" --label nightly --title "Nightly contract run failed against payload@latest" --body "$RUN_URL"; fi
```

`beta` (4.0.0-beta.7 today) is outside the peer range and informational: it can fail without failing the run. A `latest` failure opens or updates one issue labelled `nightly` (create the label in Task 44).

**Step 2: Run it once by hand.** Run `gh workflow run nightly.yml` (the developer, after pushing). Expected: `latest` green.

**Step 3: Commit.**

```bash
git add .github/workflows/nightly.yml
git commit -m "ci: run the session contract nightly against payload latest and beta"
```

### Task 42: CodeQL and Dependabot

**Files:**
- Create: `.github/workflows/codeql.yml`, `.github/dependabot.yml`

**Step 1: Write `.github/workflows/codeql.yml`, complete.**

```yaml
name: CodeQL

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '41 4 * * 1'

permissions:
  contents: read

jobs:
  analyse:
    permissions:
      contents: read
      security-events: write
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: github/codeql-action/init@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
        with:
          languages: javascript-typescript, actions
          queries: security-extended
      - uses: github/codeql-action/analyze@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
```

**Step 2: Write `.github/dependabot.yml`, complete.** The cooldown mirrors pnpm's `minimumReleaseAge`.

```yaml
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
    cooldown:
      default-days: 7
    open-pull-requests-limit: 5
    groups:
      payload:
        patterns: ['payload', '@payloadcms/*']
      simplewebauthn:
        # Read both changelogs before merging: these are exact pins on purpose (review L9).
        patterns: ['@simplewebauthn/*']
      dev-tooling:
        dependency-type: development
        exclude-patterns: ['payload', '@payloadcms/*', '@simplewebauthn/*']
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    cooldown:
      default-days: 7
    groups:
      actions:
        patterns: ['*']
```

Dependabot keeps SHA pins and updates the version comment. CODEOWNERS on `/.github/` means every such PR needs a maintainer.

**Step 3: Commit.**

```bash
git add .github/workflows/codeql.yml .github/dependabot.yml
git commit -m "ci: add CodeQL and grouped Dependabot updates with a cooldown"
```

### Task 43: Release through Changesets and npm trusted publishing

> **Implemented as (2026-11-06):** `npm publish` run in the repository ignores `publishConfig.exports` (only pnpm applies it) and would ship a manifest pointing at `src/`. So `scripts/publish.mjs` publishes the tarball `pnpm pack` makes, after `scripts/check-package.mjs` has checked that tarball, with `--provenance`. `changesets/action` then pushes lightweight tags through the GitHub API, so design §10's signed tags are not met (an open decision in `docs/release-setup.md`).

**Files:**
- Create: `.github/workflows/release.yml`, `scripts/publish.mjs`
- Modify: `package.json` (`release` script)

`changeset publish` calls `pnpm publish` in a pnpm repo, and no source confirms that pnpm supports npm's OIDC trusted publishing. npm documents trusted publishing for `npm publish` (npm 11.5.1 or later). So the publish step is `npm publish`, with pnpm only for install and build. `npm publish` generates provenance automatically under trusted publishing.

**Step 1: Write `scripts/publish.mjs`, complete.** `changesets/action` runs the publish command on every push to `main` that has no pending changesets, so it must be a no-op when the version is already on npm.

```js
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

const { name, version } = JSON.parse(readFileSync('package.json', 'utf8'))
let published = false
try {
  published = execFileSync('npm', ['view', `${name}@${version}`, 'version'], { encoding: 'utf8' }).trim() === version
} catch {
  published = false // E404: not published yet
}
if (published) {
  console.log(`${name}@${version} is already on npm; nothing to publish.`)
  process.exit(0)
}
const tag = version.includes('-') ? 'next' : 'latest'
execFileSync('npm', ['publish', '--access', 'public', '--tag', tag], { stdio: 'inherit' })
// changesets/action reads "New tag:" lines to create the GitHub release.
execFileSync('pnpm', ['changeset', 'tag'], { stdio: 'inherit' })
```

Set `"release": "pnpm build && node scripts/publish.mjs"` in `package.json`.

**Step 2: Write `.github/workflows/release.yml`, complete.**

```yaml
name: Release

on:
  push:
    branches: [main]

permissions: {}

concurrency:
  cancel-in-progress: false
  group: release

jobs:
  release:
    environment: release
    permissions:
      contents: write
      id-token: write
      pull-requests: write
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
      - uses: ./.github/actions/setup
      - name: npm with trusted publishing (11.5.1 or later)
        run: npm install -g npm@11.21.2
      - run: npm audit signatures
      - run: pnpm test:unit
      - uses: changesets/action@ae32849d5ba541f9ae29e40e22a623bc13562f51 # v2.1.2
        with:
          commit: 'chore: release'
          publish: pnpm release
          title: 'chore: release'
          version: pnpm changeset version
        env:
          GITHUB_TOKEN: ${{ github.token }}
```

Notes:
- `environment: release` is a protected environment with a required reviewer (Task 44), so nothing publishes without a person approving the run.
- There is no `NPM_TOKEN` anywhere. npm's trusted publisher entry names this repository, the workflow file `release.yml` and the environment `release` (Task 44).
- `actions/setup-node` is not given `registry-url` here, because that writes an `.npmrc` expecting `NODE_AUTH_TOKEN`, which trusted publishing doesn't use.
- Checkout keeps its credentials in this one job, because `changesets/action` pushes the version branch with them.

**Step 3: Rehearse.** Create a changeset (`pnpm changeset`, patch, "First public pre-release") with `"version": "0.1.0-rc.0"` in `package.json`. Then run `node scripts/publish.mjs` locally with `npm publish --dry-run` swapped in. Expected: the dry run lists only `dist/`, `LICENSE`, `README.md`, `SECURITY.md` and `package.json`.

**Step 4: Commit.**

```bash
git add .github/workflows/release.yml scripts/publish.mjs package.json
git commit -m "ci: release with Changesets and npm trusted publishing"
```

### Task 44: Repository and registry settings (the developer does these; the plan lists them)

> **Implemented as (2026-11-06):** the checklist is `docs/release-setup.md`, with additions found while building CI: the 3.93.0 cells can't install before 2026-11-11, the open question whether npm allows a trusted publisher before the package exists, the signed-tags decision, the release environment's approval on every push to `main`, and checks for the first CI and Dependabot runs.

These are dashboard steps for Ian. Write them as a checklist in `docs/release-setup.md`, then commit it with `git add docs/release-setup.md && git commit -m "docs: list the repository and npm settings the release depends on"`.

- [ ] Claim the npm organisation `the-digital-stride` (fallback `thedigitalstride`, design §12). Protect the npm account with a passkey, and set the package to "Require two-factor authentication and disallow tokens".
- [ ] npm → package → Settings → Trusted publisher → GitHub Actions: organisation `The-Digital-Stride`, repository `payload-passkeys`, workflow `release.yml`, environment `release`. (The package must exist first: publish `0.1.0-rc.0` once by hand with `npm publish --provenance --access public` from a clean checkout, then switch to trusted publishing and revoke any token.)
- [ ] GitHub → Settings → Environments → `release`: a required reviewer, and deployment branches limited to `main`.
- [ ] Branch protection on `main`: pull requests required, one approving review, review from code owners, dismissal of stale approvals, the required checks `static`, every `integration` job, `migrations`, `e2e` and `CodeQL`, signed commits, no force pushes, and administrators included.
- [ ] Tag protection: only the release workflow creates `v*` / `@the-digital-stride/payload-passkeys@*` tags, and tags are signed (design §10).
- [ ] Settings → Code security: private vulnerability reporting, Dependabot alerts and security updates, secret scanning and push protection.
- [ ] Settings → Actions → General: "Require actions to be pinned to a full-length commit SHA" (or an allowlist), and workflow permissions "Read repository contents".
- [ ] Replace `<maintainer-handle>` in `.github/CODEOWNERS`.
- [ ] Create the `nightly` issue label.
- [ ] GitHub account of every maintainer protected by a passkey.

## Milestone M6: first adopter (ianhancock.co.uk)

### Task 45: Instructions for adopting the plugin on ianhancock.co.uk (for a later session)

> **Implemented as (2026-11-06):** the instructions, corrected to the built package, are in `docs/adoption-ianhancock.md`.

This task is a set of instructions for a future session working in `/Users/ianhancock/My Repos/ianhancock`. **Nothing in that repo is changed by this plan.** Follow that repo's `CLAUDE.md`:
- create a branch first (`passkeys-sign-in`, from an up-to-date `main`);
- commit, never push;
- the dev server is Ian's: never start one and leave it running, and never run `pnpm build` while his is running;
- use the `payload` skill for the Payload work;
- UK English in anything a person reads.

Facts about that repo as of 2026-11-06 (re-check before starting):
- `src/payload.config.ts`:
  - sets no `serverURL` and no `csrf`;
  - sets `cors: [getServerSideURL()]` and `admin.user: Users.slug`;
  - uses `mongooseAdapter` with `MONGODB_URI` and a pinned `dbName`.
- `src/utilities/getURL.ts` `getServerSideURL()` returns, in order:
  1. `NEXT_PUBLIC_SERVER_URL`;
  2. `https://${VERCEL_PROJECT_PRODUCTION_URL}` (the production domain, even on preview builds);
  3. `http://localhost:3100`.
- `src/collections/Users/index.ts`: `auth: true`, a `name` field, `useAsTitle: 'name'`, all access `authenticated`.
- Plugins are assembled in `src/plugins/index.ts`.
- `package.json` engines are `^18.20.2 || >=20.9.0`, with pnpm 11 and native build approvals in `pnpm-workspace.yaml` (`allowBuilds`).
- Local development shares the production Atlas database, and the e2e suites use one throwaway user per spec file.

Steps:

1. **Check prerequisites.**
   - The Vercel project's Node version is 22 or later (Settings → Build and Deployment).
   - Change `engines.node` in `package.json` to `>=22.12.0`.
   - Run `pnpm add -E @the-digital-stride/payload-passkeys@<version>`.
   - If `pnpm-workspace.yaml` has `minimumReleaseAge`, the new release must be older than it, or be listed in `minimumReleaseAgeExclude`.
2. **Set `csrf` before anything else** (review M4). Today the empty list means Payload accepts the admin cookie from any origin. In `src/payload.config.ts` add:
   ```ts
   csrf: [
     getServerSideURL(),
     ...(process.env.VERCEL_URL ? [`https://${process.env.VERCEL_URL}`] : []),
     ...(process.env.VERCEL_BRANCH_URL ? [`https://${process.env.VERCEL_BRANCH_URL}`] : []),
   ],
   ```
   The preview entries keep the admin working on preview deployments, which today works only because `csrf` is empty. Check the admin on a preview deployment before going further.
3. **Add the plugin** in `src/plugins/index.ts`:
   ```ts
   passkeysPlugin({
     origins: [getServerSideURL()],
     rateLimit: async ({ key, req }) => {
       if (process.env.VERCEL !== '1') return true
       const { rateLimited } = await checkRateLimit('passkeys', { headers: req.headers, rateLimitKey: key })
       return !rateLimited
     },
     rpID: new URL(getServerSideURL()).hostname,
     rpName: 'Bits & Blogs',
   }),
   ```
   - `rpID` and `origins` are explicit because `serverURL` isn't set.
   - In production they resolve to the production domain. On preview builds they also resolve to the production domain (`VERCEL_PROJECT_PRODUCTION_URL`), so `*.vercel.app` previews show password sign-in only, as designed.
   - Locally they resolve to `localhost:3100`. Because local development shares the Atlas database, a passkey made locally is stored with RP ID `localhost` and shows as "Made for localhost" on the live site. Say so in the PR.
   - Add `@vercel/firewall` (exact) for the rate-limit hook. Ian creates a WAF rate-limit rule with ID `passkeys` in the Vercel dashboard (ask once with AskUserQuestion; it is a dashboard step only he can take).
4. **Generate.** Run `pnpm generate:importmap` and `pnpm generate:types`. MongoDB needs no migration. The plugin's `passkeysManager` `ui` field and hidden `passkeyUserHandle` field are admin-only, which breaks that repo's rule that every field has a frontend use. Record them as an exception, the way `generatorRunId` is.
5. **Document.** In that repo's `CLAUDE.md` under "Payload config", add a bullet:
   - the plugin, where it is configured, and the RP ID rule;
   - that previews are password-only;
   - the `passkeys:reset` command;
   - that the `passkeys`, `passkey-challenges` and `passkey-challenge-uses` collections are plugin-owned.
6. **Test.**
   - Ask Ian to restart his dev server.
   - On `http://localhost:3100/admin`, sign in with the password. Expect the enrolment prompt. Add a passkey (Touch ID), sign out, and sign in with the button.
   - Add `tests/e2e/passkeys.e2e.spec.ts`. It uses its own throwaway user `passkeys-e2e@payloadcms.com` (that repo's convention: one user per spec file, created and deleted by the spec) and a CDP virtual authenticator as in Task 36. Cover: enrol, sign out, sign in with the button, remove. `afterAll` deletes the user, and its passkeys go with it.
   - Run `pnpm lint`, `pnpm exec tsc --noEmit`, `pnpm test:int` and `pnpm test:e2e tests/e2e/passkeys.e2e.spec.ts`, after checking what owns port 3100.
7. **Ship.**
   - Commit on the branch; Ian pushes.
   - On the preview deployment, check that password sign-in works and that the note shows.
   - After the merge, check production. Run `pnpm payload passkeys:reset --collection users --email <Ian's email>` once against a throwaway user, to prove recovery works on Atlas.
   - Keep the site on the plugin's `0.x` for two weeks before 1.0.0 (pre-1.0 checklist).

## Pre-1.0 checklist

- [ ] Every task above is done, and CI (the full matrix, migrations, e2e, CodeQL) is green on `main`.
- [ ] The nightly `latest` run has been green for 7 consecutive nights.
- [ ] **A separate adversarial security review**, by a reviewer who did not write or plan this code, driven by a written threat model. Its scope:
  - session minting and revocation;
  - challenge single use and binding under concurrency on all three adapters;
  - multi-collection isolation;
  - CSRF and Origin handling with and without `serverURL`/`csrf`;
  - the fresh-session rule and re-authentication;
  - the enumeration and timing of sign-in failures;
  - rate-limit bypasses through spoofed `x-forwarded-for`;
  - the client bundle;
  - open redirects;
  - the recovery CLI;
  - the supply chain and release workflow (pinning, OIDC, environment protection).

  Every High and Medium finding is fixed, or accepted in writing, before 1.0.0. The report is kept in `docs/security/`.
- [ ] `docs/design.md` updated with every item in "Design points this plan changes or settles".
- [ ] The decision on AAGUID icons (licence and size) recorded. Names-only ships unless a licence is found.
- [ ] Manual check in real browsers and authenticators:
  - Chrome and Edge on Windows (Windows Hello);
  - Safari on macOS and iOS (iCloud Keychain / Apple Passwords);
  - Chrome on Android (Google Password Manager);
  - Firefox;
  - the 1Password and Bitwarden extensions;
  - cross-device sign-in by phone QR code (hybrid);
  - a hardware security key (expect a device-bound passkey with a counter).
- [ ] Accessibility check: keyboard-only use of the button, the manager, both modals and the prompt, and VoiceOver and NVDA announcements for errors and progress.
- [ ] Copy review by Ian: UK English, tone, and no US spellings in `en.ts` or the README.
- [ ] `useAuth()` behaviour checked on Payload 3.91+ (`authSession.expiresAt`). v1 only calls `setUser`, but the stay-signed-in reminder must still arm after a passkey sign-in.
- [ ] npm trusted publishing proven on a release candidate: provenance shows on npmjs.com, and `npm audit signatures` passes in a consumer project.
- [ ] ianhancock.co.uk has run a `0.x` release for two weeks without an incident, and recovery was exercised once.
- [ ] `SECURITY.md` reporting route tested (open and close a test advisory).
