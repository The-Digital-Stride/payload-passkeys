# Payload 3 extension points for a passkey / PIN / lock-screen plugin

Verified against installed source: payload, @payloadcms/next, @payloadcms/ui, all **3.90.2** (pinned in the repo).
Latest stable on GitHub: **v3.93.0** (2026-11-04). v4 is at **4.0.0-beta.7**. Checked via `gh release`.

Path shorthand (pnpm symlinks resolved):
- `PL` = `node_modules/.pnpm/payload@3.90.2_graphql@16.14.2_typescript@5.9.3/node_modules/payload/dist`
- `NX` = `node_modules/.pnpm/@payloadcms+next@3.90.2_…_1af5bccf…/node_modules/@payloadcms/next/dist`
- `UI` = `node_modules/@payloadcms/ui/dist`

## 0. Version-drift warnings (read first)

- **3.91.0 changed the idle logic.** Backport #17854 ("activity-aware auth sessions", original #17481) breaks `useAuth().tokenExpirationMs`, which is replaced by `useAuth().authSession.expiresAt`. The installed 3.90.2 has only `tokenExpirationMs` (`UI/providers/Auth/index.d.ts:55`). A plugin reading either must feature-detect both. The 3.91+ AuthProvider also records mouse, keyboard, focus and route activity, refreshes the token from it, coordinates tabs by BroadcastChannel, and exports `AuthSessionDebug`.
- **v4 beta**:
  - Adds `auth.refreshTokens` (#19040).
  - Adds a shared `createAuthToken` used by login and reset-password (#19041).
  - Adds `extendSession`, and `sessionExpiration` on `addSessionToUser` (#19045/#19046).
  - Sets `_strategy` automatically for custom strategies (#19313). Today the strategy must set it itself.
- 3.93.0 adds `auth.passwordHashIterations`. Not relevant to a passkey plugin.
- `Config.plugins` and `Plugin` are typed `@experimental` (`PL/config/types.d.ts:59-68`). They carry `order`, `slug` and `options` for cross-plugin discovery.

## 1. Custom auth strategies

**Types** (`PL/auth/types.d.ts:137-165`):
```
AuthStrategyFunctionArgs = { canSetHeaders?, headers: Request['headers'], isGraphQL?, payload, req?: PayloadRequest, strategyName? }
AuthStrategyResult       = { responseHeaders?: Headers, user: ({ _strategy?: string, collection?: string } & TypedUser) | null }
AuthStrategy             = { authenticate: AuthStrategyFunction, name: string }
```
Config: `collection.auth.strategies?: AuthStrategy[]` (`types.d.ts:239`).

**`req` is passed in 3.90.2.** `executeAuthStrategies` is called with `req` from `createPayloadRequest` (`PL/utilities/createPayloadRequest.js:80`) and from `auth` (`PL/auth/operations/auth.js:9`). The Next `initReq` (`NX/utilities/initReq.js`) calls it **without `req`**, so `req` is undefined for server-rendered admin views. Do not depend on `req` inside `authenticate`; use `headers` and `payload`.

**Evaluation order** (`PL/index.js:418-446`):
1. Walk `config.collections` in order. For each auth collection, push its `auth.strategies`, then its `<slug>-api-key` strategy if `useAPIKey`.
2. If any auth collection has local strategy enabled, push `local-jwt` (`JWTAuthentication`) **last**.
3. Plugin strategies therefore run before the built-in JWT. The list is **global across all auth collections**, so a strategy must check which collection it serves.

**Loop** (`PL/auth/executeAuthStrategies.js:10-31`):
- Each strategy is tried in order and wrapped in try/catch. Throws are logged and swallowed.
- The first result with a truthy `user` wins.
- `responseHeaders` are merged between strategies.
- **A strategy cannot veto.** Returning `{ user: null }` just falls through to the next strategy, including `local-jwt`. This is the hard limit for lock enforcement (see section 4).

**What a returned user needs:** `user.collection = '<slug>'` and `user._strategy = '<name>'`. Both are used in these places:
- `refresh` checks `req.user.collection === collectionConfig.slug`.
- `me`, `logout` and `canAccessAdmin` read `user.collection`.
- `getAccessResults` uses `user.collection` and compares it with `admin.user` (`PL/auth/getAccessResults.js:10-17`).
- `initReq` falls back to `admin.user` if it is missing.

Also set `user._sid` if you want core `refresh` and `logout` to find the session (`refresh.js:47`, `logout.js:48`).

**`local-jwt` behaviour** (`PL/auth/strategies/jwt.js`):
- It extracts the token via `extractJWT`, in `auth.jwtOrder` order (default JWT, Bearer, cookie). The cookie is `${config.cookiePrefix}-token`, where `cookiePrefix` is **global** (default `payload`) (`PL/auth/extractJWT.js:11-17`).
- It verifies with `jose` HS256 using `payload.secret`, and requires the protected header `authVersion === 1`.
- It reads `{ id, collection, sid }` from the claims.
- It **rejects any collection with `disableLocalStrategy` truthy** (line 97). With `useSessions`, it requires `sid` to be present in `user.sessions` (lines 103-110).
- It falls back to `admin.autoLogin` if verification fails.

**`disableLocalStrategy`** (`PL/auth/types.d.ts:190-199`): `true | { enableFields?: true, optionalPassword?: true }`. Effects:

| Effect | Source |
|---|---|
| Built-in email/password/salt/hash/lock/verify/sessions fields are omitted unless `enableFields` is set | `PL/auth/getAuthFields.js:13` |
| `login`, `forgotPassword`, `resetPassword`, `unlock`, `verifyEmail` and `registerFirstUser` throw Forbidden | each operation file |
| `local-jwt` rejects the collection | `jwt.js:97` |
| `refresh` skips session extension | `refresh.js:48` |
| `logout` skips sessions only when `=== true`; an object still revokes the session | `logout.js:27` |
| `LoginView` does not render `<LoginForm>` | `NX/views/Login/index.js:75` |
| `/create-first-user` redirects to the admin | `NX/views/Root/index.js:196` |
| The login view and `beforeLogin`/`afterLogin` slots still render | `NX/views/Login/index.js` |

`optionalPassword` is only declared in the types and consumed by the admin Edit/Auth UI (it makes the password optional when creating users). Nothing in core reads it at runtime.

**Consequence:** if the plugin sets `disableLocalStrategy`, it must ship its own cookie/JWT strategy and its own logout. If it keeps local strategy on, the built-in `local-jwt` already authenticates any JWT the plugin mints, which is much less work.

## 2. Issuing a normal Payload session from custom code

**What `loginOperation` does** (`PL/auth/operations/login.js:30-362`):
1. It throws Forbidden if `disableLocalStrategy`. It requires `password`, so **there is no passwordless path** in `payload.login` or the login endpoint.
2. It runs `beforeOperation`, then loads the user with `payload.db.findOne` (raw doc including `hash` and `salt`).
3. It runs `checkLoginPermission`, which throws if the user is missing or `isUserLocked(lockUntil)`.
4. It authenticates the password. On failure it calls `incrementLoginAttempts` when `maxLoginAttempts > 0`.
5. It starts a transaction, re-checks the lock, then calls `addSessionToUser`. This mutates `user.sessions` and writes the whole raw `user` via `db.updateOne`, **returning `sid`**.
6. It calls `getFieldsToSign({ collectionConfig, email, sid, user })`, then `resetLoginAttempts`.
7. It runs the `beforeLogin` hooks. These run after the session exists, and a throw triggers `revokeSession`. It then calls `jwtSign`, sets `req.user`, and runs the `afterLogin` hooks with `{ token, user }`.
8. It returns `{ exp, token, user }`.

**The cookie is set by the endpoint handler, not the operation** (`PL/auth/endpoints/login.js`): `generatePayloadCookie({ collectionAuthConfig, cookiePrefix: config.cookiePrefix, token })` goes into `Set-Cookie`. The handler also deletes `token` from the body if `auth.removeTokenFromResponses`.

**Cookie** (`PL/auth/cookies.js:65-80`):
- Name is `${cookiePrefix}-token`. `HttpOnly` and `Path=/` are always on.
- `Expires` is now plus `auth.tokenExpiration` (default 7200 s).
- `SameSite` comes from `auth.cookies.sameSite` (default `'Lax'`; `true` maps to `Strict`; `'None'` forces `Secure`).
- `Domain` and `Secure` come from `auth.cookies`.

**Sessions** (`PL/auth/sessions.js`, `PL/auth/baseFields/sessions.js`):
- `useSessions` defaults to `true` (`PL/collections/config/defaults.js:129,144`).
- The `sessions` array has `{ id, createdAt, expiresAt }` rows. Field access is read-own, update false, and it is hidden in the admin.
- The session `expiresAt` equals `now + tokenExpiration`.
- `removeExpiredSessions` is applied on add and on refresh.
- Core revokes sessions on:
  - `logout`, which removes `req.user._sid`, or all sessions with `?allSessions=true`;
  - login failure after session creation;
  - brute-force lockout, where `incrementLoginAttempts` removes sessions created in the last 20 s (`incrementLoginAttempts.js:~75-95`).
- The sessions field is only added when `!disableLocalStrategy` or `enableFields`.

**Exports available to a plugin:**

| Export | From | In 3.90.2 |
|---|---|---|
| `jwtSign({ fieldsToSign, secret, tokenExpiration })` | `payload` | yes |
| `getFieldsToSign({ collectionConfig, email, sid, user })` | `payload` | yes |
| `executeAuthStrategies`, `JWTAuthentication`, `extractJWT` | `payload` | yes |
| `checkLoginPermission`, `loginOperation`, `refreshOperation`, `logoutOperation` | `payload` | yes |
| `incrementLoginAttempts`, `resetLoginAttempts` | `payload` | yes |
| `generatePayloadCookie`, `generateExpiredPayloadCookie`, `parseCookies` | `payload` (via `export *`) and `payload/shared` | yes |
| `addSessionToUser`, `removeExpiredSessions` | `payload/shared` only | yes |
| `revokeSession` | none | **no**; do the filter plus `db.updateOne` yourself |
| `isUserLocked` | none | **no**; trivial to reimplement |
| `createAuthToken` | none | v4 beta only |

**Cleanest supported recipe for "log in after verifying a passkey"** (no private imports, works on 3.90.2+ with local strategy ON). In a collection endpoint (`POST /api/<usersSlug>/passkey/login/finish`):
1. Verify the WebAuthn assertion.
2. Load the user with `req.payload.db.findOne({ collection, where: { id } })`. Use the **db** call, as core does, because `addSessionToUser` writes the whole object back.
3. Run `checkLoginPermission({ req, user })`, and reject if `auth.verify` and `!user._verified`.
4. Run `{ sid } = await addSessionToUser({ collectionConfig, payload, req, user })`.
5. Run `fieldsToSign = getFieldsToSign({ collectionConfig, email: user.email, sid, user })`.
6. Run `{ token, exp } = await jwtSign({ fieldsToSign, secret: payload.secret, tokenExpiration: collectionConfig.auth.tokenExpiration })`.
7. Respond with `Set-Cookie: generatePayloadCookie({ collectionAuthConfig: collectionConfig.auth, cookiePrefix: payload.config.cookiePrefix, token })`, and return the `{ exp, token?, user }` shape the admin expects. Remember `removeTokenFromResponses`.
8. Run the collection's `beforeLogin` and `afterLogin` hooks manually if you want parity. They are **not** run for custom flows, because they are called only inside `loginOperation` (`login.js:286-315`). Core's hook signatures are `{ collection, context, req, user }` and `{ ..., token }`.

That is about 15 lines of reimplementation built from public exports. It breaks only if `JWT_AUTH_VERSION` or the claim shape changes. v4's `createAuthToken` will replace steps 4-6 later.

**Refresh** (`PL/auth/operations/refresh.js`):
- It needs `req.user` in the right collection, and extends the matching `sid` session by `tokenExpiration`.
- It re-signs the JWT from `req.user` (including `sid`) and sets the cookie. A collection `hooks.refresh` hook can fully replace the result, and `afterRefresh` runs after.
- Sessions are only extended if `useSessions && !disableLocalStrategy`.

**Logout** (`PL/auth/endpoints/logout.js`, `PL/auth/operations/logout.js`):
- `afterLogout` hooks run first, then the session is removed, then `Set-Cookie` is set to an expired cookie.
- It requires `req.user.collection` to match the endpoint's collection.

## 3. Admin UI hooks

`admin.components` (`PL/config/types.d.ts:690-775`): `actions`, `afterDashboard`, `afterLogin`, `afterNav`, `afterNavLinks`, `beforeDashboard`, `beforeLogin`, `beforeNav`, `beforeNavLinks`, `graphics{Icon,Logo}`, `header[]`, `logout.Button`, `Nav`, `providers[]`, `settingsMenu[]`, `views{[key]: AdminViewConfig, account?, dashboard?}`. Also `admin.routes` (`types.d.ts:825-875`), `admin.autoRefresh`, `admin.dependencies`, `admin.importMap.generators`.

**Login view** (`NX/views/Login/index.js`):
- Renders the Logo, then `beforeLogin`, then `<LoginForm>` (only if local strategy is not disabled), then `afterLogin`. These are RSC slots receiving `{ i18n, locale, params, payload, permissions, searchParams, user }`.
- If `user` is already set, it redirects to `getSafeRedirect(searchParams.redirect)`.
- `LoginForm` (`NX/views/Login/LoginForm/index.js`) is a fixed `<Form action=/api/<admin.user>/login method=POST onSuccess={setUser(data)}>` with email/username and password. **You cannot inject fields or a button into it.** `beforeLogin` and `afterLogin` render outside the `<Form>`, so a passkey button there must run its own fetch and then call `useAuth().setUser(json)` followed by `router.push(redirect)`.

**Replacing the login view:** yes.
- Route-key override: `admin.components.views.login = { Component: 'pkg/rsc#View' }`. `getRouteData.js:88-129` maps `config.admin.routes[key]` to a view key, so `views.login` overrides `/login`, keeping the minimal template and the `login` base class. Only `views.account`/`dashboard` are typed, but the index signature allows any key, and `getCustomViewByKey` does `config.admin.components.views[viewKey]`.
- Path-based: any `views[key] = { Component, path: '/foo', exact? }` adds a new route at `/admin/foo`.
- `admin.routes.login` and `.logout` / `.inactivity` / `.unauthorized` etc. can be renamed.
- **Public-route pitfall:** `isPublicAdminRoute` (`NX/utilities/isPublicAdminRoute.js`) whitelists `createFirstUser, forgot, login, logout, inactivity, unauthorized, reset` plus `/<slug>/verify/<token>`. A **custom view path is exempt from the admin-access redirect** (`isCustomAdminView`, `Root/index.js:125-133`), so **custom views are not auth-protected by Payload**. The view must check `initPageResult.req.user` itself, as this repo's generator view does. This is the lock-screen view's trap.
- `LoginView` redirects an authenticated user away, so a "locked" screen at `/login` is not possible without replacing the view.

**Providers** (`NX/layouts/Root/index.js:113-135`, `NestProviders.js`): `admin.components.providers` are nested **inside `RootProvider`**, so `AuthProvider`, `ConfigProvider` and the modal provider are all available via hooks. They wrap **every** admin route, including login, logout and custom views.
- They are RSC by default and receive `{ i18n, payload, permissions, user }` server props, plus `children`.
- A `'use client'` provider is the natural home for an idle timer and a full-screen lock overlay.
- Providers render even when logged out, so check `user` first.

**AuthProvider** (`UI/providers/Auth/index.js`), `useAuth()` exposes: `user, token, tokenExpirationMs, permissions, setUser, logOut, refreshCookie(forceRefresh?), refreshCookieAsync(skipSetUser?), refreshPermissions, setPermissions, fetchFullUser`.
- `setUser(res)` takes the login/refresh response (`{ user, token|refreshedToken, exp }`). It re-arms two timers: a reminder at `exp - min(60 s, remaining/2)` and a forced logout at `exp`.
- At the reminder, if `admin.autoRefresh` is false (default) it opens the `stay-logged-in` modal (`StayLoggedInModal`, `UI/elements/StayLoggedIn/index.js`, slug `stayLoggedInModalSlug`). Its "stay" button calls `refreshCookie()` and its "log out" button pushes to the logout route. If `autoRefresh` is true it silently refreshes instead.
- At expiry it clears the user and `router.replace`s to `admin.routes.inactivity` (`/logout-inactivity?redirect=…`), which renders `LogoutInactivity`, then logs out and redirects to login.
- `refreshCookie()` is **token-expiry based, not activity based**, in 3.90.2. It fires on each `pathname` change and refreshes only if less than `2 * forceLogoutBufferMs` remains.
- `logOut()` posts `/api/<user.collection>/logout`. `refreshCookieAsync` posts `/api/<userSlug>/refresh-token`.
- **It is not a true idle timer.** A lock screen cannot reuse it directly in 3.90.2. The plugin should run its own activity listeners, and optionally call `refreshCookie(true)` while the user is active, so the JWT does not expire under a locked screen. In 3.91+ the provider has activity tracking and `authSession`; see section 0.
- There is no built-in hook to veto or defer the inactivity redirect. Raising `tokenExpiration` is the supported knob.

**Components for plugins:**
- String paths use `'pkg/client#Name'` or `'pkg/rsc#Name'`, or `{ path, exportName, clientProps, serverProps }` (`PL/config/types.d.ts:32-38`).
- The consumer must run `pnpm generate:importmap`. A plugin can also supply `admin.importMap.generators` or `admin.dependencies`.
- Core examples: `'@payloadcms/plugin-seo/client#MetaTitleComponent'`, `'@payloadcms/plugin-multi-tenant/rsc#TenantSelector'`, `'@payloadcms/storage-vercel-blob/client#VercelBlobClientUploadHandler'`.
- A client component file needs `'use client'`. The `./client` and `./rsc` package exports exist so client and server code never share an entry.

**Other useful slots:**
- `admin.components.actions`: top-right of every page (a "Lock now" button).
- `settingsMenu`: the gear popup above the logout button.
- `logout.Button`: replace the logout button.
- `header`: global header.
- A `type: 'ui'` field with `admin.components.Field` on the users collection: a "Manage passkeys" panel on the account/user edit screen.

## 4. Enforcing a lock server-side

| Mechanism | REST | GraphQL | Local API w/ `req` | Server-rendered admin views | Verdict |
|---|---|---|---|---|---|
| Custom strategy returning `user: null` | no veto (falls to `local-jwt`) | no veto | no veto | no veto | **cannot block** (`executeAuthStrategies.js:10-31`) |
| Strategy that **returns a marked user** (`_locked: true`) | user still truthy; default `({req:{user}})=>!!user` passes | same | same | same | unsafe unless every access fn is wrapped |
| Wrap every collection/global `access.*` and `access.admin` | yes | yes | only if `overrideAccess:false` | `canAccessAdmin` gate redirects (`getAccessResults.js:12`, `Root/index.js:125`) | works, but invasive, and `overrideAccess:true` Local API and custom endpoints bypass it |
| `beforeOperation` hooks per collection | yes | yes | yes | partly | needs injecting into every collection; skips globals, and `auth`/`me`/`access` are not covered |
| **Revoke the session** (remove `sid` from `user.sessions`) | yes | yes | yes | yes | **reliable**: `local-jwt` returns `user: null` (`jwt.js:103-110`) |
| `admin.components.providers` overlay | no | no | no | client-only, cosmetic | UX only |
| Next middleware / `proxy.ts` | n/a | n/a | n/a | n/a | plugins cannot add it; the host app must |

**Recommendation:**
- **Hard lock = server-side session revocation plus a client overlay.** The sid-bound `local-jwt` check is the only choke point every surface passes through (it runs in `initReq`, `createPayloadRequest` and `auth`).
- The plugin keeps a `{ userId, credential policy, locked-at }` record. The overlay's unlock calls a plugin endpoint that verifies passkey or PIN and mints a **new** session and cookie, as in section 2.
- This needs `useSessions: true`, which is the default (and an auth collection with the sessions field).
- Without sessions there is no revocable server-side state. In that case the only real guard is a stateless plugin strategy that sets the marker, plus wrapped access.

**Soft lock (overlay only)** protects against shoulder-surfing and an unattended screen. It does not stop a stolen cookie replaying against `/api`. Say so in the docs.

**Admin RSC pages:** `initReq` caches per request. A locked marker would need `access.admin` to deny, which redirects to `/unauthorized` (`handleAuthRedirect`), not to a lock view.

## 5. Plugin-side storage

**Adding a collection** (see `plugin-redirects/dist/index.js` for the idiom): return `{ ...config, collections: [...(config.collections || []), passkeyCollection] }`.
- Access: owner-only via a query constraint, e.g. `read: ({ req: { user } }) => user ? { user: { equals: user.id } } : false`. Make `create` and `update` false (written only via endpoints with `overrideAccess`), and `delete` owner-only (revocation).
- Hide it with `admin: { hidden: true }`. `payload-kv` does the same (`PL/kv/adapters/DatabaseKVAdapter.js`).
- Add `lockDocuments: false` and consider `timestamps: true`.
- Relationship: `{ name: 'user', type: 'relationship', relationTo: <authSlug>, required: true, index: true }`. For multiple auth collections use a polymorphic `relationTo: [..]` or one credential collection per auth collection.
- Compound uniqueness: `indexes: [{ fields: ['user','credentialID'], unique: true }]` (`collections/config/types.d.ts:573`) or `unique: true` on `credentialID`.

**Fields (DB-neutral):**
- `credentialID`: text, `unique: true, index: true`. Store as base64url.
- `publicKey`: text (base64url COSE bytes). **There is no binary field type**, so use base64 text everywhere.
- `counter`: number.
- Also `transports` (select hasMany or json), `deviceType`, `backedUp`, `aaguid`, `label`, `lastUsedAt`, `createdAt`.
- Avoid putting WebAuthn challenges on the user doc.

**Adding fields to an existing auth collection** (e.g. `passkeyEnabled`, `pinHash`, `totpSecret`):
- `config.collections.map(c => slug matches ? { ...c, fields: [...c.fields, ...pluginFields] } : c)`.
- Secrets must be `hidden: true` with `access: { read: () => false, create: () => false, update: () => false }`, matching how `hash` and `salt` are done (`PL/auth/baseFields/auth.js`).
- Prefer a separate collection over user-doc fields, so the plugin does not widen the `users` read surface.

**Challenge storage** is DB-neutral through `payload.kv` (`PL/index.js:373`, `PL/kv/index.d.ts`): the default `databaseKVAdapter` creates the hidden `payload-kv` collection (`config/defaults.js:170-172`). A `kv-redis` package exists. The API is `get/set/delete/has/keys/clear`. There is **no TTL and no atomic compare-and-delete**, so store an `expiresAt` in the value, and delete after use. A race on one-time challenges is mitigated by deleting before verifying.

**Indexes and migrations:**
- Mongo: indexes come from `index`/`unique`/`indexes`, and Mongoose creates them on startup. No schema migration is needed.
- Postgres/SQLite (drizzle): adding a collection or fields **requires the host to run `payload migrate:create` and `payload migrate`**, because `push` is dev-only. The plugin README must state this.
- Also tell consumers to run `payload generate:types` and `generate:importmap`.
- Unique indexes behave consistently, except that SQL treats NULLs as distinct, so avoid optional unique fields.
- Hidden or sensitive fields are not excluded from the migration.

**Adding fields to the user doc affects `getFieldsToSign` only if `saveToJWT` is set** (`PL/auth/getFieldsToSign.js`). Keep secrets out of the JWT. If you do add a claim, e.g. an `amr`/auth-level flag for step-up, set `saveToJWT` on a field or sign it yourself in your own `jwtSign` call. A claim added to `fieldsToSign` is carried by the core refresh only if it is a `saveToJWT` field, because `refresh` re-derives claims from the user doc.

## 6. Custom endpoints

- **Collection endpoints**: `collection.endpoints: Endpoint[]` mount at `/api/<slug>/<path>`. **Root endpoints**: `config.endpoints` mount at `/api/<path>`. Matching is `path-to-regexp`, the first match wins, and `req.routeParams.collection` is injected (`PL/utilities/handleEndpoints.js:137-182`).
- **Collection endpoints order:** on sanitize, user endpoints come first and the built-in auth endpoints are pushed after (`PL/collections/config/sanitize.js:77-97`). So **a plugin `POST /login` on the users collection overrides the built-in login**, and so can `/refresh-token`, `/logout` and `/me`. This is the supported way to add a second factor to the stock login: respond "challenge required" instead of a cookie.
- **Handler**: `(req: PayloadRequest) => Response | Promise<Response>`, a Web `Request` extended with `payload`, `user`, `t`, `i18n`, `searchParams`, `routeParams`, `context`, `responseHeaders` and `headers`. `req.user` is already authenticated by the strategy chain (`createPayloadRequest.js:80-90`).
- **Body**: only the **internal** POST/PATCH endpoints are wrapped with `addDataAndFileToRequest` (`PL/utilities/wrapInternalEndpoints.js`). A plugin endpoint must `await addDataAndFileToRequest(req)` (exported from `payload`) and then read `req.data`. It throws `APIError('Invalid JSON')` on bad JSON.
- **Response cookies and headers**:
  - Return `Response.json(body, { headers })`.
  - `handleEndpoints` merges `req.responseHeaders` with the handler's headers and then applies `headersWithCors` (`handleEndpoints.js:200-208`).
  - `mergeHeaders` appends rather than overwrites, so multiple `Set-Cookie` values survive.
  - Core builds the session cookie as `Set-Cookie: generatePayloadCookie(...)`.
- **CSRF**: `config.csrf: string[]` (default `[]`; `serverURL` is auto-added if set, `config/sanitize.js:341`). It is enforced **only inside `extractJWT` for the cookie method** (`PL/auth/extractJWT.js:11-38`):
  - Origin present: allowed only if the allowlist is empty or contains it.
  - No Origin and csrf configured: falls back to `Sec-Fetch-Site` in `same-origin`, `same-site` or `none`.
  - Otherwise the cookie is ignored and the request is anonymous.
  - There is **no CSRF check on unauthenticated endpoints**. Passkey login endpoints are unauthenticated by nature. WebAuthn protects them by binding the `origin` and `rpID` in the signed clientData, so verify `expectedOrigin` and `expectedRPID` strictly. Do not trust the `Origin` header.
  - Bearer and `JWT` header tokens skip CSRF entirely.
- **CORS**: `config.cors` is applied to every endpoint response by `headersWithCors`; the OPTIONS preflight is answered automatically.
- **Rate limiting**: Payload has no generic rate limiter. For per-user throttling, `incrementLoginAttempts({ collection, payload, user })` and `resetLoginAttempts({ collection, doc, payload, req })` are exported from `payload` and reusable:
  - They require the `loginAttempts` and `lockUntil` fields, which exist only when `maxLoginAttempts > 0` and local strategy is on (or `enableFields`) (`getAuthFields.js:41-43`).
  - `incrementLoginAttempts` locks for `auth.lockTime` at `maxLoginAttempts`. It also **wipes sessions created in the last 20 s** on lockout.
  - They share the password counter, so a PIN brute-force would also lock password login for that user. That may be desirable, or may be a DoS vector.
  - Per-IP limiting needs an external store (or `payload.kv` with an IP key).
  - Check `isUserLocked` (`lockUntil`) yourself before verifying a PIN.

## 7. Multiple auth collections and `admin.user`

- `config.admin.user` names the single collection that logs into the admin. Login view, `AuthProvider`, `LogoutClient` and the `/me` and `/refresh-token` calls all use it. `canAccessAdmin` is true only when `user.collection === admin.user` (`getAccessResults.js:11`) or the collection's `access.admin` approves.
- Other auth collections can still sign in through the API (`/api/<slug>/login`) but not through the admin UI.
- `auth.strategies` from all collections are merged into one global list (section 1), so a plugin strategy must filter by collection itself.
- **Plugin option design:** `collections?: string[]` defaulting to `[config.admin.user ?? 'users']`. Throw if a listed slug lacks `auth`. Always read `incomingConfig.admin?.user` (default `'users'`) rather than assuming. `plugin-multi-tenant` does the same style of check (`throw Error('An auth enabled collection was not found')`).
- The `useAuth()` hook and the client config expose only `admin.user`. Per-collection UI needs `getEntityConfig({ collectionSlug })`.

## 8. Plugin conventions in Payload 3

- **Signature:** `(options) => (incomingConfig: Config) => Config | Promise<Config>`. Never mutate `incomingConfig`. Spread arrays and objects (`docs/plugins/build-your-own.mdx`).
- **`enabled`:** the docs template uses `enabled?: boolean`. `plugin-multi-tenant` returns the config untouched when `pluginConfig.enabled === false` (`src/index.ts:25`). Sensible practice is to still add collections and fields when disabled, so DB schema and types do not shift, and to skip only hooks, strategies, endpoints and components. SEO and redirects have no `enabled` option.
- **Function-valued keys** (`onInit`, hooks): call the incoming one first and then add yours. Arrays: append to `admin.components.providers` and similar (`plugin-multi-tenant` spreads `incomingConfig.admin?.components?.providers`).
- **Ordering:** plugins execute in array order, and then defaults and sanitisation run (docs). `Plugin.order` and `slug` are experimental for cross-plugin discovery.
- **Core plugin package layout** (seo `package.json` exports; multi-tenant `src/exports`):
  - `.` is the server entry (the config function). It is Node-safe and does not import React client code.
  - `./client` is client components (`'use client'`), e.g. `plugin-seo/dist/exports/client.js`.
  - `./rsc` is server components (multi-tenant).
  - `./types`, `./fields`, `./utilities` and `./translations/languages/*` hold the rest.
  - Components are referenced from config as `'<pkg>/client#Name'` or `'<pkg>/rsc#Name'`.
  - Peer deps: `payload` (exact version match in core), `@payloadcms/ui` and `react` for UI plugins.
  - Build: swc to `dist`, tsc for types, plus a `copyfiles` step for `.scss` and assets.
  - Redirects, seo and the template also merge translations with `deepMergeSimple` and register `i18n.translations`.
- **Official template** is `templates/plugin` in `payloadcms/payload` (create-payload-app `-t plugin`): `src/{components,endpoints,exports,index.ts}`, `dev/` (a Next app with its own `payload.config.ts` and `int.spec.ts`), Vitest plus Playwright, `pnpm dev:generate-importmap`, pinned to payload 3.82.1 at the time of fetching. The separate `payloadcms/plugin-template` repo is stale (payload ^2).
- **Docs gaps:** `build-your-own.mdx` does not cover admin component paths, import maps or naming. Tag the GitHub repo `payload-plugin`, use semver, and state the Payload compatibility per major.
- **Core plugin precedents for security-sensitive endpoints:** plugin-seo re-checks collection and document access with `overrideAccess:false` in its endpoints (`authorizeGenerateTarget`). Copy that discipline.

## 9. Existing MFA / TOTP / passkey code

- **Core and monorepo packages** (`gh api repos/payloadcms/payload/contents/packages`): no auth, MFA or passkey package. Packages are admin-bar, codemod, create-payload-app, db-*, drizzle, email-*, graphql, kv-redis, live-preview-*, next, oxlint-*, payload-cloud, plugin-cloud-storage, plugin-ecommerce, plugin-form-builder, plugin-import-export, plugin-mcp, plugin-multi-tenant, plugin-nested-docs, plugin-redirects, plugin-search, plugin-sentry, plugin-seo, plugin-stripe, richtext-lexical, sdk, storage-*, tanstack-start, transformer-sharp, translations, typescript-plugin, ui. No enterprise-only auth package was found either.
- **Roadmap and discussions:**
  - #2555 "Implementing 2FA" and #3298 "Improved Authentication" are open feature requests. #3298 lists 2FA via OTP, revoking all tokens, and idle-session detection.
  - The idle-session part has since shipped partly in 3.91 (#17854).
  - `auth.refreshTokens` is landing in v4 beta (#19040).
  - No committed core roadmap item for passkeys or TOTP.
- **Community plugins to study or differentiate from** (both are TOTP, not passkeys):
  - `@assamlabs/payload-2fa` (discussion #17955): TOTP, QR setup, backup codes, custom auth collections, "protected login when 2FA is enabled", no middleware.
  - `@plutotcool/payload-plugin-two-factor` (#17535): TOTP, encrypted secrets, HMAC-signed cookie keyed by the Payload secret, uses **edge middleware**.
  - A `payload-auth-plugin` / `better-auth` replacement route is mentioned in #3298. I did not review these.
- **No passkey/WebAuthn plugin was surfaced** in the repo searches (GitHub issue and discussion search for passkey, webauthn, 2fa, mfa, totp). An npm and GitHub search for existing passkey plugins is still worth doing before committing to a name.

## Shape-by-shape integration points (summary)

1. **Passkey sign-in alongside email+password (recommended v1):**
   - Keep local strategy ON.
   - Collection endpoints `/passkey/register/{options,verify}` and `/passkey/login/{options,verify}`, with the session mint from section 2.
   - A client `beforeLogin` or `afterLogin` component for the "Sign in with passkey" button, which calls `setUser` and redirects.
   - A `type: 'ui'` field for managing credentials.
   - Hidden `passkey-credentials` collection.
   - Challenges in `payload.kv`.
2. **Passkey instead of password:**
   - Requires `disableLocalStrategy: { enableFields: true }`.
   - The plugin must supply its own cookie JWT strategy (set `collection`, `_strategy`, `_sid`), its own refresh and logout endpoints, and a custom login view. `LoginForm` is hidden automatically.
   - `registerFirstUser` and forgot-password are disabled. Provide a bootstrap path.
   - Recommend deferring this.
3. **Second factor (passkey or TOTP):** override collection `POST /login` to return a challenge token after the password step, then complete in a second endpoint. `beforeLogin` cannot do this cleanly: the stock form sends only email and password, and a throw loses the session and cookie. A `beforeLogin` hook can enforce a second factor only if `req.data` carries the code.
4. **Idle lock screen:**
   - `admin.components.providers` client component with activity listeners and an overlay.
   - Lock action calls a plugin endpoint that **revokes the session** (and records who locked).
   - Unlock verifies passkey or PIN and mints a new session.
   - Optionally keep the token alive with `useAuth().refreshCookie(true)`.
   - Handle both `tokenExpirationMs` (3.90) and `authSession.expiresAt` (3.91+).
5. **Step-up re-auth:** no core concept. Implement as a plugin cookie or claim (short-lived signed cookie or `payload.kv` entry keyed by `sid`) checked in wrapped access or `beforeOperation` hooks for chosen operations, plus a modal in a provider.

## Hard limitations found

- No passwordless path in `loginOperation`, and `beforeLogin`/`afterLogin` are not run for custom flows.
- An auth strategy cannot veto. Locking is only reliable by revoking sessions (or wrapping all access).
- `LoginForm` is not extensible, and it disappears with `disableLocalStrategy`.
- Custom admin views are not auth-protected by Payload.
- Plugins cannot add Next middleware or `proxy.ts`.
- `revokeSession` and `isUserLocked` are not exported, and `addSessionToUser` is only on `payload/shared`.
- `req` is undefined inside strategies when called from server-rendered admin views (`initReq`).
- `useAuth().tokenExpirationMs` is removed in 3.91+.
- `payload.kv` has no TTL or atomic delete.
- SQL adapters need the host to generate migrations. There is no binary field type.
- `cookiePrefix` and `csrf` are global, not per collection.
