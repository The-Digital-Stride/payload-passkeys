# Adversarial security review: payload-passkeys design (docs/design.md, 2026-11-06)

Reviewed against Payload 3.90.2 source (`node_modules/.pnpm/payload@3.90.2_graphql@16.14.2_typescript@5.9.3/node_modules/payload/dist`, written `PL/` below), the installed `@payloadcms/db-mongodb` and `@payloadcms/next`, the `payloadcms/payload` main branch for `packages/drizzle/src/deleteOne.ts`, SimpleWebAuthn master `verifyAuthenticationResponse.ts`, and WebAuthn L3 §7.1/§7.2. Each finding is labelled CONFIRMED (checked in source or spec) or PLAUSIBLE (reasoned, not reproducible from a design document).

No critical findings: nothing in the design lets an anonymous attacker sign in. The highs are places where the design's own guarantees (fresh session, single use, owner-only, server-enforced lock) do not hold as written.

---

## High

### H1. The password re-check for "fresh session" has no lockout, so a stolen cookie enables online password brute force. CONFIRMED

**Attack.** An attacker holding a stolen admin cookie more than 10 minutes old calls `register/options`, gets `reauth_required`, and then submits passwords to the re-auth check at will. Nothing in §4.1 step 2 mentions `incrementLoginAttempts`, `lockUntil` or `checkLoginPermission`, so the check is unthrottled; Payload's own login has the lockout precisely because this is an online oracle. Once the password is found the attacker registers their own passkey and keeps access after the cookie expires.

**Evidence.** `PL/auth/operations/login.js:165-186` wraps `authenticateLocalStrategy` in `incrementLoginAttempts` and re-checks `checkLoginPermission`. `authenticateLocalStrategy` is **not exported** from `payload` (grep of `PL/index.js` finds `checkLoginPermission`, `incrementLoginAttempts`, `resetLoginAttempts`, `jwtSign`, `getFieldsToSign`, but no `authenticateLocalStrategy`), so the design's primary option does not exist in 3.90.2 anyway. Design §4.1 step 2, §12 "Password re-check helper … not exported".

**Change.** Make the fallback the design: re-auth *is* `payload.login({ collection, data: { email, password }, req })` (the exported `loginOperation`). It brings lockout, `beforeLogin` hooks and a brand-new session whose `createdAt` is now, which is exactly the "fresh session" the rule wants. Set the returned cookie so the browser moves onto the new session, and revoke the old `sid`. Require `rateLimit` with action `reauth` keyed by user id as well.

### H2. Phase-2 unlock discloses credential IDs and the lock has no way to bind the unlocker to the locked user. CONFIRMED (design gap)

**Attack.** After `POST /passkeys/lock` the session is revoked, so the unlock options request is anonymous. The design says the assertion is "limited to the locked user's passkeys through `allowCredentials`". Whoever the client names, the server would return that user's credential IDs and transports: an anonymous endpoint that tells anyone which user IDs have passkeys, how many, and on what transport (iCloud vs security key). It also undercuts §6 "discoverable sign-in never names an account". And "the server refuses a different user" needs a server-held notion of who is locked, which nothing in §11 creates.

**Evidence.** §11 bullet 3; `PL/auth/strategies/jwt.js:110-116` (a revoked `sid` returns `user: null`, so the lock-screen requests carry no identity).

**Change.** `POST /passkeys/lock` must mint a **lock ticket**: an HMAC (keyed from `payload.secret`, domain-separated) over `{ collection, userId, lockedAt, exp = session exp }`, returned as an HttpOnly `__Host-` cookie. Unlock options accept only that ticket, and use **empty `allowCredentials`** (discoverable) so nothing is listed; unlock verify compares the asserted passkey's user to the ticket and refuses otherwise. The password unlock sends the ticket too, and the server, not the client, fixes the email.

### H3. Multiple auth collections: polymorphic `user` plus colliding IDs lets a passkey from collection B sign in as collection A's user. CONFIRMED (ID collision), PLAUSIBLE (that the implementation would miss it)

**Attack.** Endpoints are per collection (`/api/<slug>/passkeys/sign-in/verify`). The verify looks up the passkey by `credentialId`, reads `passkey.user` (polymorphic: `{ relationTo, value }`) and mints a session for the *endpoint's* collection with `user.id = value`. On Postgres and SQLite the default `idType` is `serial`, so `customers` id 7 and `users` id 7 both exist. A low-privilege `customers` user registers a passkey, then presents it to `/api/users/passkeys/sign-in/verify`; `checkLoginPermission` and `mintSession` run against `users` id 7, and `getFieldsToSign` writes `collection: 'users'` into the JWT. The same shape breaks `read`/`delete` access (`{ user: { equals: req.user.id } }` ignores `relationTo`) and `rename`/`delete` ownership checks.

**Evidence.** §3 "passkeys.user is polymorphic when more than one is configured"; §4.2 step 4 only says "checks its user still exists in that collection"; `PL/auth/getFieldsToSign.js:114-122` takes `collection` from `collectionConfig`, not from the passkey.

**Change.** Store `collection` as a plain text field on the passkey row as well as the relationship, and require `passkey.collection === endpointCollection.slug` (and `passkey.user.relationTo === slug`) before anything else. Access functions use `and: [{ 'user.relationTo': { equals: user.collection } }, { 'user.value': { equals: user.id } }]`. Add a multi-collection integration test on Postgres with deliberately colliding IDs.

### H4. `useSessions: false` silently voids the fresh-session rule, the lock and all revocation. CONFIRMED

**Attack.** A host sets `useSessions: false` (a documented, supported option). `addSessionToUser` returns `sid: undefined`; the JWT has no `sid`; there is no `sessions` row and no `req.user._sid`. The fresh check in §4.1 ("the current session's `createdAt` … for `req.user._sid`") has nothing to read, so it either always refuses (dead feature) or, if coded as "no row, no restriction", always passes, and a stolen cookie can plant a passkey at any time. Phase 2's "lock is server-enforced by revoking the session" cannot revoke anything, so the lock becomes the overlay-only theatre the design itself rejects.

**Evidence.** `PL/auth/sessions.js:14-49` (`sid` only when `useSessions`); `PL/auth/strategies/jwt.js:110-118` (session check only when `useSessions`); `PL/auth/operations/logout.js:27` (no revocation without sessions).

**Change.** Validate at config time: a configured collection with `useSessions: false` throws when `lock.enabled`, and for v1 either throws or falls back to **password-only re-auth** (H1) for registration with a logged warning. Say so in the README and in §12.

---

## Medium

### M1. The `sign-in/verify` and `mintSession` response body leaks the raw user document. CONFIRMED

**Attack.** §3 step 1 loads the user with `payload.db.findOne` (needed because `addSessionToUser` writes the whole doc back) and step 9 returns "`{ exp, token?, user }`". The raw doc carries `hash`, `salt`, `sessions` (every live `sid`), `apiKey`, `resetPasswordToken` and the new `passkeyUserHandle`. Core avoids this with `sanitizeInternalFields` and `applyUserReadAccess`; neither appears in the design. Any XSS or the browser's network panel then yields the password hash for offline cracking and every session id.

**Evidence.** `PL/auth/operations/login.js:169, 319-331`.

**Change.** Build the response user with `payload.findByID({ id, collection, overrideAccess: false, user: mintedUser, depth: auth.depth })` after minting, exactly as `/me` does (`PL/auth/operations/me.js`). Add a contract test asserting none of `hash`, `salt`, `sessions`, `apiKey`, `passkeyUserHandle` appear in any plugin response.

### M2. Anonymous `sign-in/options` writes a row per call; nothing bounds it by default. CONFIRMED

**Attack.** `rateLimit` defaults to `() => true`. An attacker loops `POST /api/users/passkeys/sign-in/options` and inserts a challenge row (plus a unique-index entry) each time; pruning only removes rows older than 5 minutes, so the steady state is attacker-rate × 300 s rows in the production database, on the same Atlas cluster as the content. The design's "per-user caps on outstanding challenges" cannot apply to a ceremony with no user.

**Evidence.** §3 `rateLimit` default; §6 "Rate limiting"; §4.2 step 2.

**Change.** (a) A hard **global cap on outstanding anonymous challenges** (e.g. 500); when hit, `sign-in/options` returns 429 and password login is unaffected. (b) Log a warning at startup when `rateLimit` is the default in `NODE_ENV=production`. (c) Cap one outstanding sign-in challenge per browser-key cookie: re-issuing replaces the previous row rather than adding one. (d) Document that the `key` the hook receives is `x-forwarded-for` and is trustworthy only behind a proxy that sets it.

### M3. "Deleted before verification" is not single use on Postgres or SQLite, nor through the Local API on Mongo. CONFIRMED

**Attack.** Two concurrent `verify` requests carrying the same assertion. Drizzle's `deleteOne` is `selectDistinct … limit(1)` then `findFirst` then `deleteWhere(eq(id))`, three statements; both requests read the row, both "delete" it, both verify the same signature and both mint a session. Payload's `deleteOperation` is also find-then-`db.deleteOne` on every adapter. Only Mongo's `db.deleteOne` (`findOneAndDelete`) is atomic, and only when called with `where: { challenge }` and its return value checked.

**Evidence.** `packages/drizzle/src/deleteOne.ts` (main): `selectDistinct … query.limit(1)`, `db.query[tableName].findFirst`, then `this.deleteWhere({ where: eq(this.tables[tableName].id, docToDelete.id) })`. `@payloadcms/db-mongodb/dist/deleteOne.js:29`. Design §4.1 step 6, §6 "Replay".

**Change.** Make the consume step a **unique insert**, which is atomic on every adapter: at verify, `create` a row in a `passkey-challenge-uses` collection (or a second unique field) keyed by the challenge value; a unique-constraint error means replay, abort. Then delete the challenge row. Keep the pre-verification ordering. Add a concurrency test that fires the same assertion twice in parallel on all three adapters and expects exactly one session.

### M4. Signed-in plugin endpoints are CSRF-able on hosts with an empty `csrf` list, and the body parser accepts HTML forms. CONFIRMED

**Attack.** `extractJWT` accepts the cookie from *any* `Origin` when `config.csrf` is empty (`PL/auth/extractJWT.js:20-24`), and `csrf` is empty unless `serverURL` or `csrf` is set. If the host also sets `auth.cookies.sameSite: 'None'` (common for cross-domain frontends), a malicious website can POST a `multipart/form-data` form whose `_payload` field is JSON; `addDataAndFileToRequest` parses it into `req.data` (`PL/utilities/addDataAndFileToRequest.js:31-53`). `delete`, `rename` and phase-2 `lock` then run with the victim's cookie: passkeys removed, admin locked at will. The design's statement that "Payload's `csrf` allowlist still governs" is true only when the list is non-empty.

**Change.** On every signed-in plugin endpoint: require `Content-Type: application/json` (refuse multipart), and require `Origin` (or, absent that, `Sec-Fetch-Site: same-origin`) to be one of the configured `origins`; the `__Host-` browser-key cookie already does this for the two ceremony endpoints. At config time, warn when `csrf` is empty and refuse when `sameSite === 'None'` without a `csrf` list.

### M5. Password lockout also locks the passkey out, so anyone who knows an admin's email can keep them out. CONFIRMED

**Attack.** Defaults are `maxLoginAttempts: 5`, `lockTime: 600000` (`PL/collections/config/defaults.js:125-127`). Five wrong passwords lock the account; §3 step 2 then refuses the passkey too via `checkLoginPermission` (`PL/auth/operations/login.js:22-29`). One request every ten minutes denies both sign-in paths indefinitely. A passkey assertion cannot be guessed, so the lock protects nothing on this path.

**Change.** For passkey sign-in, check `_verified` and that the user exists, but **do not refuse on `lockUntil`**; log `passkeys.signed_in_while_locked`. Keep `resetLoginAttempts` on success (a passkey proves the holder). Document the choice. Phase 2's password unlock still goes through the stock login and keeps its lockout.

### M6. Removing a passkey, or running the reset CLI, leaves the attacker's sessions alive. PLAUSIBLE

**Attack.** The design's persistence threat is a planted passkey. When the owner notices and deletes it (or runs `payload-passkeys reset`), every session that passkey minted survives for `tokenExpiration` and can be refreshed indefinitely by `/refresh-token` (`PL/auth/operations/refresh.js:48-67`), so the attacker keeps working and may re-register.

**Change.** The reset CLI always empties `sessions` on the user (`sessions: []`, the "log out of all sessions" write in `PL/auth/operations/logout.js:45-46`). The UI's remove dialogue offers "Also sign out everywhere", ticked by default when the passkey was used in the last 24 hours. Log both.

### M7. The counter policy as written cannot be implemented with the chosen library and keys on the wrong flag. CONFIRMED

**Attack / defect.** SimpleWebAuthn throws `Response counter value … was lower than expected` whenever `(counter > 0 || credential.counter > 0) && counter <= credential.counter` (master `verifyAuthenticationResponse.ts`). Passing the stored counter means a synced passkey that once reported a non-zero value, or a cloned security key, hard-fails before the design's "warn only" logic runs; passing `0` disables the check and the design must do its own. The design keys refusal on `backedUp: false` (BS), which flips when a user turns sync off; device-bound is BE = 0, i.e. `credentialDeviceType === 'singleDevice'`. The library also does **not** compare `credentialDeviceType`/`credentialBackedUp` against the stored record, and §7.2 of the spec expects the RP to verify BE never changes (research `external.md` §1.7).

**Change.** Pass `credential.counter` as stored and catch the counter error to apply policy, or pass `0` and implement: refuse when `deviceType === 'singleDevice'` and `newCounter <= stored` with either non-zero; otherwise log `counter_regression` and keep the stored value (never write a lower counter). Refuse and log when `credentialDeviceType` differs from the stored `deviceType`. Update `backedUp` when BS changes.

### M8. Phase-2 lock: the overlay can be dropped by a tab message, and the locked page's content stays readable. PLAUSIBLE

**Attack.** (a) Tab A's unlock broadcasts "unlocked" over `BroadcastChannel`; tab B drops its overlay. Same-origin only, so spoofing needs XSS, but a stale or replayed message, or a tab whose cookie jar differs (private window), leaves B showing the admin with a dead session and a confusing failure on the next save. (b) Physical access to a plugin-locked laptop: the DOM behind the opaque layer is intact (`inert` only blocks interaction), as is the Next.js router cache of previously visited pages and anything in `localStorage`. DevTools, "Select all/copy" via the accessibility tree, or deleting the overlay node reveal drafts, user emails and any API key shown on the account page. The server lock stops *new* reads, not what is already rendered.

**Change.** A tab drops its overlay only after its own `GET /api/<slug>/me` returns a user with a live session; channel messages are hints to re-check, never state. For (b), document plainly that the lock protects the server and the next request, not the current screen; offer `lock.clearOnLock: 'navigate-home' | 'none'` that routes to the dashboard before locking when the current view is sensitive (users collection, API keys), and never store form state in `localStorage` while locked.

### M9. RP ID and origin defaults when `serverURL` is unset, wrong, or a public suffix. CONFIRMED (defaults), PLAUSIBLE (misconfig frequency)

**Attack / defect.** Payload allows `serverURL` to be empty; the Vercel template derives it from env at runtime. `new URL('').hostname` throws, and `rpID` of `localhost` or a preview `*.vercel.app` host on production yields a plugin that silently fails every ceremony (the status endpoint hides the button, so the owner sees nothing). An `rpID` that is a public suffix (`vercel.app`, `co.uk`) is refused by browsers with `SecurityError`. None of these are attacks, but they are the misconfigurations the README will be blamed for, and an `origins` entry that is not under `rpID` is accepted silently.

**Change.** At config time: throw when neither `rpID` nor a parseable `serverURL` exists; throw when `rpID` is not equal to or a registrable-suffix of every origin's host (ship the small public-suffix check or refuse the known hosting suffixes); log at `info` the resolved `rpID` and `origins` on boot. `status` should return the mismatch reason to the admin UI (not to anonymous callers) so the Passkeys section can say *why*.

---

## Low

### L1. IP addresses in every log line. CONFIRMED (design), GDPR
§6 logs the request IP on `.signed_in`, `.sign_in_failed`, etc. An IP is personal data under UK GDPR; security logging is a legitimate interest, but it must be documented, minimised and retention-bound, and `payload.logger` output goes wherever the host's logs go (Vercel, Datadog) with the host's retention. **Change:** `logging: { ip: 'none' | 'truncated' | 'full' }`, default `truncated` (/24 and /48); never log IP on success; add a privacy note to the README naming the lawful basis.

### L2. API-key and non-cookie callers can manage passkeys. CONFIRMED
`APIKeyAuthentication` returns a user with `_strategy: 'api-key'` and no `_sid` (`PL/auth/strategies/apiKey.js:54-58`). Such a request on `register/options` is never fresh (good), but `rename`/`delete`, and `lock`, work with a leaked API key or a Bearer JWT, which also skips CSRF entirely (`extractJWT.js:3-9`). **Change:** require `req.user._strategy === 'local-jwt'` and a present `_sid` on every signed-in plugin endpoint.

### L3. GraphQL and depth exposure of the plugin collections. PLAUSIBLE
Both collections enter the GraphQL schema; `passkeys.user` populates on read. **Change:** `graphQL: false` on `passkeys` and `passkey-challenges`; `maxDepth: 0` on `user`; `defaultPopulate` empty.

### L4. `passkeyUserHandle` on the user document is exposed to the whole-document write-back race, and `credProps.rk` is unchecked. CONFIRMED (write-back), PLAUSIBLE (race)
`addSessionToUser` and `refresh` write the entire user document back (`PL/auth/sessions.js:37-43`, `refresh.js:58-67`). A login or refresh racing the first `register/verify` can persist a copy without the new handle; the stored passkey then never matches at sign-in (§4.2 step 4) and the user believes they are protected. Separately, an authenticator that ignores `residentKey: 'required'` yields a non-discoverable credential that never appears in a discoverable sign-in. **Change:** create the handle in `register/options` and copy it onto the passkey row (`userHandle`); compare `response.userHandle` to the *row*, not the user. Refuse registration when `credProps.rk === false`; warn when absent.

### L5. Redirect validation: reuse Payload's. CONFIRMED
`getSafeRedirect` is exported from `payload/shared` (`PL/utilities/getSafeRedirect.js`) and already handles `//`, `/\`, `/%2F`, control characters and `/javascript:`. **Change:** call it with `fallbackTo: adminRoute` and additionally require the result to start with `adminRoute + '/'` or equal it, rather than writing a second validator.

### L6. Timing and the status endpoint. PLAUSIBLE
An unknown credential returns before any signature work; a known one runs ECDSA. **Change:** verify a fixed dummy assertion on the unknown path. `status` is harmless, but rate-limit it and return only `{ available: boolean }` to anonymous callers.

### L7. Browser-key cookie details. PLAUSIBLE
Decide `Secure`/`__Host-` from the configured origin's scheme, never from `req.url` (behind TLS-terminating proxies Node may see `http`). Two tabs starting ceremonies overwrite one cookie: name it per ceremony type, or carry the key in the response body and send it back in the request body with the cookie only as the binding. Set `Path=/` and no `Domain` (required by `__Host-`), `Max-Age=300`.

### L8. `mintSession` skips `beforeOperation`/`afterOperation` for `login`. CONFIRMED
Hosts commonly hang audit or geo rules there (`PL/auth/operations/login.js:38-43, 335-341`). **Change:** document the gap in §12 and, if `buildBeforeOperation` is exported in a later minor, call it; otherwise expose a plugin hook `onSignIn` with the same args.

### L9. Supply chain and release. PLAUSIBLE
SimpleWebAuthn is a single-maintainer package with a `@peculiar/*`, `tsyringe`, `reflect-metadata` tree; `@simplewebauthn/browser` is dependency-free. **Change:** pin exact versions and bump by hand; pnpm `minimumReleaseAge` (or the equivalent) of 7 days; a test that the `./client` entry's dependency graph contains only `@simplewebauthn/browser` and `@payloadcms/ui`; pin every GitHub Action to a commit SHA; CODEOWNERS on `.github/workflows/`; `npm audit signatures` in CI; publish `provenance` and tell users to verify it.

---

## Things the design gets right

- Public keys in a separate collection written only through `overrideAccess` endpoints, never on the user document, which the whole-document write-back in `addSessionToUser` would otherwise race.
- `userVerification: 'required'` at both ceremonies with `requireUserVerification: true` at verify; `attestation: 'none'`; 64-byte random `user.id`; `excludeCredentials`; refusing already-registered credential IDs (spec §7.1 step 26).
- Discoverable sign-in with empty `allowCredentials` and one generic error, so the login path names no account.
- Origin and RP ID taken from the signed `clientDataJSON`, not from headers.
- Local strategy kept on, so Payload's own JWT strategy, refresh, logout, `/me` and forgot-password keep working and the plugin mints nothing hand-rolled; `authVersion` comes from `jwtSign`.
- The fresh-session idea is the right instinct against cookie theft, and `createdAt` is untouched by refresh (`refresh.js:55` changes only `expiresAt`), so the window really is from login.
- Server-enforced lock by session revocation rather than an overlay or middleware: the `sid` check in `jwt.js:110-116` is the one choke point every surface passes.
- Contract tests per Payload minor and a nightly `latest`/`beta` run for the undocumented helpers; a client-import boundary test; trusted publishing with provenance.
