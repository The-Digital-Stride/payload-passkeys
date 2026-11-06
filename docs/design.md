# Payload passkeys plugin: brief and design

Status: **Agreed design, not yet built** (2026-11-06). The implementation plans are in `docs/plans/`; the evidence behind every decision is in `docs/research/` (`external.md`: standards, libraries, prior art, other CMSs; `payload-internals.md`: Payload 3.90.2 source, with file and line references; `security-review.md`: adversarial review of this design, every finding accepted and folded in below, tagged H1–H4, M1–M9, L1–L9).

## 1. Brief

A public, open-source Payload CMS 3 plugin that lets admins sign in to the Payload admin with a **passkey**: Touch ID, Face ID, Windows Hello, an Android fingerprint, or the device's own PIN or password when biometrics aren't available. It must work on any Payload 3 site and any database adapter.

| | |
|---|---|
| Package | `@the-digital-stride/payload-passkeys` (npm scope must be lowercase; the npm organisation `the-digital-stride` still has to be claimed) |
| Repository | `The-Digital-Stride/payload-passkeys` on GitHub (not created yet; this repo is local only) |
| Licence | MIT |
| Supports | Payload `>=3.90.0 <4`, Node `>=22`, MongoDB, Postgres and SQLite adapters. Payload 4 once stable, with code written to v4's import rules now |
| First adopter | ianhancock.co.uk (Payload 3.90.2, MongoDB, Vercel), then The Digital Stride's client sites |

### Decisions from the interview (2026-11-06)

| # | Question | Decision |
|---|---|---|
| D1 | Core shape | Sign in with a passkey. Other shapes later or never. |
| D2 | "Passcode" | The device's own PIN or password, used by the passkey itself. The plugin stores and checks no PIN. |
| D3 | Audience | Public npm package. Open source does not weaken it; the release pipeline is hardened instead (section 10). |
| D4 | Code home | A new standalone repo built from Payload's plugin template, with a dev app inside. |
| D5 | Password | Passkeys sit **alongside** email and password and are optional per admin. The local strategy is never disabled, so Payload's forgot-password stays the recovery path. |
| D6 | Login UI | A "Sign in with a passkey" button under the stock form, through the documented `afterLogin` slot. No replacement login view. |
| D7 | Later phases | **Phase 2: idle lock screen.** Not planned: step-up, passwordless, admin management of others' passkeys (each may be revisited). |
| D8 | Versions | Payload >=3.90, Node 22+. |
| D9 | Enrolment | A dismissible prompt after a password sign-in, plus a Passkeys section on the Account page. |
| D10 | Audit | Structured `payload.logger` lines only in v1. |
| D11 | Lock screen without a passkey | The lock box asks for the password instead. |
| D12 | Idle time | 15 minutes by default, configurable. |
| D13 | Session approach | Mint a native Payload session with Payload's own helpers, isolated behind one adapter and contract-tested per Payload minor. |
| D14 | Sessions required (review H4, decided by Claude, open to change) | A configured collection with `auth.useSessions: false` is refused at config time: without sessions there is no fresh-session check, no revocation and no server-side lock. |
| D15 | Password lockout vs passkeys (review M5, decided by Claude, open to change) | A password lockout (`lockUntil`) does not block passkey sign-in, because a passkey can't be guessed and otherwise anyone knowing an admin's email could keep them out indefinitely. Logged as `passkeys.signed_in_while_locked`. |

## 2. Scope

**v1 (1.0.0):** register, list, rename and remove passkeys; sign in with a passkey; post-sign-in enrolment prompt; preview-host handling; logging; docs; CI across Payload minors and adapters; hardened release.

**Phase 2 (1.x minor):** idle lock screen (section 11).

**Out of scope:** passwordless mode, second factor after the password, step-up re-authentication, an app-level PIN, TOTP (the `payload-totp` plugin exists), conditional-UI autofill on the email field (the stock login form cannot be given `autocomplete="username webauthn"`), an audit collection, Related Origin Requests (`/.well-known/webauthn`), admins removing other users' passkeys from the UI (a CLI reset covers lost access).

## 3. Architecture

### Plugin shape

```ts
import { passkeysPlugin } from '@the-digital-stride/payload-passkeys'

plugins: [
  passkeysPlugin({
    // all optional
    enabled: true,                  // false keeps the schema, removes endpoints and UI
    collections: ['users'],         // auth collections; default [config.admin.user]
    rpID: 'example.com',            // default: hostname of serverURL
    rpName: 'Example admin',        // default: config.admin.meta.title ?? hostname
    origins: ['https://example.com'], // default: [serverURL origin]
    slugs: { passkeys: 'passkeys', challenges: 'passkey-challenges' },
    enrolmentPrompt: true,
    rateLimit: async ({ req, action, key }) => true, // host hook, e.g. Vercel WAF or Upstash
    limits: { passkeysPerUser: 20, anonymousChallenges: 500 },
    logging: { ip: 'truncated' },   // 'none' | 'truncated' | 'full'
    onSignIn: async ({ req, user, passkey }) => {}, // stands in for login beforeOperation/afterOperation (L8)
    freshSessionMinutes: 10,
    // lock: { enabled, idleMinutes: 15 } arrives in phase 2; v1 rejects it
  }),
]
```

The plugin is a plain function that spreads the incoming config (no `definePlugin` until Payload 4 settles), validates options at config time, and throws a clear error for impossible combinations:

- a listed collection without `auth`, with `disableLocalStrategy`, or with `useSessions: false` (D14);
- neither `rpID` nor a parseable `serverURL` (M9);
- an `rpID` that is a known hosting public suffix (`vercel.app`, `netlify.app`, `pages.dev`, …) or an origin whose host is not the `rpID` or under it (M9);
- `auth.cookies.sameSite: 'None'` with an empty `csrf` list (M4).

It warns at boot when `csrf` is empty, and in production when `rateLimit` is left at its default (M2, M4), and logs the resolved `rpID` and origins at `info`.

### What it adds

**Collections** (written only through the Local API, so every adapter behaves the same):

- `passkeys`: `admin.hidden`, `lockDocuments: false`, `graphQL: false`, timestamps.
  - Fields: `user` (relationship to the auth collection(s), required, indexed, `maxDepth: 0`), `collection` (text, required: the auth collection's slug, checked before anything else, H3), `userHandle` (text: the WebAuthn user ID this passkey was made with, L4), `credentialId` (text, unique, base64url), `publicKey` (text, base64url COSE), `counter` (number), `transports` (json), `deviceType` (`singleDevice` | `multiDevice`), `backedUp` (checkbox), `aaguid` (text), `rpID` (text), `name` (text, max 64), `lastUsedAt` (date).
  - Access: `read` only your own, matching both collection and ID (`and: [{ collection: { equals: req.user.collection } }, { 'user.value' / user: { equals: req.user.id } }]`, H3); `create`, `update` and `delete` false through the API, so every removal goes through the guarded `/passkeys/delete` endpoint (M4). The plugin's endpoints write with `overrideAccess: true`. `publicKey`, `counter` and `userHandle` are never returned by the API (field `read: () => false`).
  - A separate collection, not fields on the user, because Payload's login and refresh write back the whole raw user document and would race the counter and `lastUsedAt`.
- `passkey-challenges`: `admin.hidden`, `graphQL: false`, every API access false.
  - Fields: `challenge` (text, unique), `type` (`registration` | `authentication`), `collection` (text), `userId` (text, optional; a relationship can't span collections), `userHandle` (text, optional), `browserKeyHash` (text), `expiresAt` (date, indexed).
- `passkey-challenge-uses`: `admin.hidden`, `graphQL: false`, every API access false. One field, `challenge` (text, unique), plus `expiresAt`. Consuming a challenge is a **create** here: a unique-constraint error means the challenge was already used. A unique insert is atomic on every adapter, whereas find-then-delete is not on Postgres, SQLite or the Local API (M3). Pruned with the challenges.

**Fields on each auth collection:**

- `passkeyUserHandle`: text, hidden, all field access false, **not unique** (it is never queried, and Mongo's sparse unique index collides on explicit nulls; 512 random bits). 64 random bytes (base64url), created in `register/options` when the user has none, and copied onto each passkey row, so a whole-document write-back racing the first registration can't orphan a passkey (L4). It is the WebAuthn `user.id`, so the email never reaches an authenticator.
- `passkeysManager`: a `ui` field rendering the Passkeys section on the Account page and the user edit view (own account only).

**Endpoints** (collection endpoints on each auth collection, so `/api/<slug>/passkeys/...`; all POST, JSON body read with `addDataAndFileToRequest`):

| Path | Auth | Purpose |
|---|---|---|
| `/passkeys/register/options` | signed in, fresh (see 4.1) | creation options |
| `/passkeys/register/verify` | signed in | verify attestation, store passkey |
| `/passkeys/sign-in/options` | anonymous | request options (discoverable, no user named) |
| `/passkeys/sign-in/verify` | anonymous | verify assertion, mint session |
| `/passkeys/rename` | signed in, owner | rename |
| `/passkeys/delete` | signed in, owner | remove (optionally signing out everywhere) |
| `/passkeys/reauth` | signed in | the password re-check for the fresh-session rule, a real `payload.login()` (H1) |
| `/passkeys/status` | anonymous or signed in | `{ available }` for anyone; for the signed-in owner also the mismatch reason, their passkeys and `signalUserId` (their WebAuthn user ID, needed by `signalAllAcceptedCredentials`; returned nowhere else) |

Collection endpoints are matched before Payload's built-ins, so every path stays under `/passkeys/` to avoid shadowing core routes such as `/login` or `/:id`.

Every endpoint refuses anything but `Content-Type: application/json`, so an HTML form posting Payload's multipart `_payload` field can't reach it (M4). The signed-in endpoints also require:

- `req.user._strategy === 'local-jwt'`, a session ID, the session **cookie** and no `Authorization` header, so a leaked API key or a JWT sent as a header can't manage passkeys (L2).

Every endpoint except `status` requires an `Origin` in the configured origins (or, with no `Origin`, `Sec-Fetch-Site: same-origin`), because Payload's `csrf` check accepts any origin when its list is empty (M4); on the anonymous ceremony endpoints this also stops other sites' visitors filling the anonymous-challenge cap.

Every endpoint calls the `rateLimit` hook with its action (M9, L6). On MongoDB the plugin builds its own indexes at boot, so replay protection doesn't depend on the host's `ensureIndexes`.

**Admin components** (by import path; `./client` and `./rsc` exports):

- `afterLogin`: `SignInWithPasskey` (client).
- `providers`: `PasskeysProvider` (client): enrolment prompt, later the lock screen.
- `ui` field: `PasskeysManager` (client) with a small RSC wrapper for server props.

**Library:** `@simplewebauthn/server` and `@simplewebauthn/browser` v14 (MIT, maintained, WebCrypto-based, array `expectedOrigin` and `expectedRPID`). Server code imports it only from endpoint and hook modules, never from anything the client bundle or `payload.config.ts`'s client components can reach; a test enforces the boundary.

### Session minting (`src/server/mintSession.ts`)

The only module that touches Payload's undocumented exports. After a verified assertion it repeats `loginOperation`'s steps without the password:

1. Load the raw user with `payload.db.findOne` (core does this because `addSessionToUser` writes the whole document back). This raw document holds `hash`, `salt`, `sessions` and `apiKey`, so it never leaves the module (M1).
2. Check the user exists and, when `auth.verify` is on, is verified. A password lockout (`lockUntil`) does **not** block a passkey (D15, M5): log `passkeys.signed_in_while_locked` and carry on.
3. Inside a transaction where the adapter supports one: `addSessionToUser` (from `payload/shared`) returns `sid` when `useSessions` is on.
4. `getFieldsToSign({ collectionConfig, email, sid, user })`.
5. Run the collection's `beforeLogin` hooks (core runs them only inside `loginOperation`); a throw revokes the new session and fails the sign-in, so host rules that block logins still apply.
6. `jwtSign({ fieldsToSign, secret: payload.secret, tokenExpiration })`, which carries the current `authVersion` claim (3.90.0 rejects tokens without it).
7. Run `afterLogin` hooks with `{ token, user }`, then the plugin's `onSignIn` option. Payload's `beforeOperation`/`afterOperation` hooks for `login` do not run here; the README says so and points to `onSignIn` (L8).
8. `resetLoginAttempts` when `maxLoginAttempts > 0` (a passkey proves the account holder). In the code this runs before the `beforeLogin` hooks, as core does.
9. Return the cookie from `generatePayloadCookie({ collectionAuthConfig, cookiePrefix, token })` and the body shape the admin expects (`{ exp, token?, user }`, honouring `removeTokenFromResponses`). The `user` in the body is re-read with `payload.findByID({ overrideAccess: false, user, depth: auth.depth })`, exactly as `/me` builds it, so field read access applies and no internal field is returned (M1).

Because the result is an ordinary Payload session, logout, "log out of all sessions", `autoRefresh`, `/me`, password-change revocation and every API keep working with no plugin code. A contract test runs this module against every supported Payload minor and the latest release nightly, so a change to the helpers or the claim shape fails CI instead of failing silently in production. When Payload 4 ships `createAuthToken`, steps 3, 4 and 6 move onto it behind the same function.

## 4. Flows

### 4.1 Registering a passkey

1. The Passkeys section (or the enrolment prompt) calls `register/options`.
2. The server requires a signed-in user of a configured collection and a **fresh session**: the current session's `createdAt` (from the user's `sessions` row for `req.user._sid`) within the last 10 minutes. Refresh changes only `expiresAt`, so the window really runs from sign-in. Otherwise it answers `{ error: 'reauth_required' }`, and the UI asks for the current password. The re-check **is a real Payload sign-in**: `payload.login()` (the exported `loginOperation`), which brings Payload's attempt counting and lockout, the host's `beforeLogin` hooks, and a brand-new session whose `createdAt` is now. Its cookie replaces the old one and the old session is revoked. A bare password comparison would hand a stolen cookie an unthrottled password oracle, and `authenticateLocalStrategy` isn't exported anyway (H1). It also calls the `rateLimit` hook with action `reauth`, keyed by user. This stops a stolen session cookie from planting the attacker's passkey for persistence.
3. Options: `residentKey: 'required'`, `userVerification: 'required'`, `attestation: 'none'`, ES256, EdDSA and RS256, `excludeCredentials` = the user's passkeys, `extensions: { credProps: true }`, timeout 5 minutes, 32-byte challenge, `user.id` = `passkeyUserHandle`, `user.name` = email (or `username` when the collection logs in by username), `user.displayName` = the `useAsTitle` field.
4. The challenge row is stored with the user, collection, type and the SHA-256 of a random browser key. The key goes to the browser in an HttpOnly, `SameSite=Strict` cookie: `Path=/`, no `Domain`, `Max-Age=300`, named per ceremony type and collection (for example `__Host-payload-passkeys-auth-users`) so two tabs or two collections don't overwrite each other. It is `__Host-` prefixed and `Secure` when the **configured origin** is HTTPS (never decided from `req.url`, which reads `http` behind a TLS-terminating proxy), and unprefixed on `http://localhost` (L7).
5. `navigator.credentials.create()` in the browser; the response goes to `register/verify`.
6. The server **consumes** the challenge before verifying, by creating its `passkey-challenge-uses` row: a unique-constraint error means replay, so it stops (M3). It then deletes the challenge row (single use, success or failure), checks it was for this user, collection, type and browser and not expired, and calls `verifyRegistrationResponse` with `requireUserVerification: true`, the origin list and the RP ID. It refuses a credential ID already stored for anyone, and refuses when `credProps.rk === false`, because a non-discoverable credential would never appear at sign-in (L4). The per-user cap (default 20 passkeys) applies.
7. Store the passkey. Default name from the AAGUID (a vendored snapshot of provider **names only**, pinned to a commit and hash: the community list has no licence and its icons are vendor logos, and it is being retired from 6 Jan 2027), editable.
8. After any change, the browser calls `PublicKeyCredential.signalAllAcceptedCredentials` where supported, so password managers drop deleted passkeys.

### 4.2 Signing in

1. `SignInWithPasskey` calls `status`; if the host does not match the RP ID it renders nothing but a short note (section 5). It also feature-detects WebAuthn and hides itself on unsupported browsers.
2. Press: `sign-in/options` returns a challenge with empty `allowCredentials` (discoverable credentials, so no email is asked for and nothing about accounts is revealed) and `userVerification: 'required'`. One outstanding sign-in challenge per browser key (re-issuing replaces it), and a global cap on outstanding anonymous challenges (default 500, then 429; password sign-in is unaffected) (M2).
3. `navigator.credentials.get()`; the response goes to `sign-in/verify`.
4. The server consumes the challenge as in 4.1 and finds the passkey by credential ID. Before anything else it requires `passkey.collection` to equal this endpoint's collection: on Postgres and SQLite, `users` 7 and `customers` 7 can both exist, so an ID alone proves nothing (H3). It then checks the user still exists, that the assertion's `userHandle` matches the passkey row's `userHandle` (L4), and calls `verifyAuthenticationResponse` (`requireUserVerification: true`). On the unknown-credential path it verifies a fixed dummy assertion, so timing doesn't reveal which credentials exist (L6).
5. Counter and flags (M7). SimpleWebAuthn throws on any non-increasing counter where either value is non-zero, so the plugin applies its own policy around it:
   - refuse when the passkey is device-bound (`deviceType: 'singleDevice'`, BE=0) and the counter didn't increase;
   - otherwise log `passkeys.counter_regression` and carry on, never writing a lower counter;
   - refuse when the reported device type differs from the stored one (BE must never change);
   - update `backedUp` when the backup state changes.
6. Update `counter` and `lastUsedAt`, then `mintSession` (section 3).
7. The client sets the user through `useAuth().setUser` and navigates to the `redirect` search parameter. It runs that through Payload's own `getSafeRedirect` (from `payload/shared`) and requires the result to sit under the admin route, otherwise it goes to the admin root, so there is no open redirect (L5).
8. An assertion naming an unknown credential gets a generic failure and the client calls `signalUnknownCredential`, so the stale passkey disappears from the user's password manager.

Every failure the user sees is one generic message ("That passkey couldn't be used. Try again or sign in with your password."); the reason goes to the log.

### 4.3 Managing passkeys

The Passkeys section lists each passkey with provider name (from the AAGUID, at display time) and a generic passkey icon, the name, created and last used dates, and whether it is synced. Rename inline; remove with a confirmation that names what remains. Removing the last passkey says the password still works. It shows only on the signed-in user's own document.

The remove dialog has an "Also sign out everywhere" tick box. It is ticked by default when the passkey was used in the last 24 hours, so removing a planted passkey also ends the sessions it made (M6).

### 4.4 Enrolment prompt

After a password sign-in, if the user has no passkey, the browser supports platform passkeys (`isUserVerifyingPlatformAuthenticatorAvailable`) and the host matches the RP ID, the provider shows a dismissible prompt: "Sign in faster with a passkey". "Not now" hides it for 30 days on that browser (localStorage); "Don't ask again" stores a flag on the passkey user record.

"Don't ask again" is localStorage only, per collection and user ID, so no schema change. "After a password sign-in" means the first admin page view in a browser session while the user has no passkeys (a user with none must have used the password).

## 5. Hosts, RP ID and previews

- RP ID defaults to the hostname of `serverURL`; origins default to the `serverURL` origin. Both can be set; origins accept several (for example apex and `www`).
- `vercel.app`, `netlify.app` and `pages.dev` are public suffixes, so every preview deployment is its own RP ID. On a host that is not the RP ID or a subdomain of it, the plugin hides the button and the Passkeys section shows "Passkeys work on example.com only". Password sign-in is unaffected. The README documents giving previews a custom domain under the production domain.
- `http://localhost` works (a secure context) with RP ID `localhost`; those passkeys never work elsewhere.
- Each passkey stores its `rpID`; changing `rpID` later breaks existing passkeys unless the new value is a parent domain, which the README warns about and the section flags per passkey.

## 6. Security model

- **What is stored:** public keys and metadata only. No secrets: the plugin adds nothing that would let a database leak sign someone in.
- **Replay:** one 32-byte challenge per ceremony, server-generated, deleted before verification, at most 5 minutes old, bound to type, user (for registration) and browser.
- **Login CSRF:** the browser-key cookie means a response only completes in the browser that started it.
- **Origin:** the signed `clientDataJSON` origin and the RP ID hash are verified against configured values. For the ceremonies themselves the `Origin` header is not trusted. The signed-in endpoints add JSON-only, an origin check of their own and `local-jwt` only (section 3), because Payload's `csrf` allowlist is empty unless configured (M4, L2).
- **Atomic single use:** consuming a challenge is a unique insert, and a parallel double-verify test runs on all three adapters (M3).
- **Multiple auth collections:** every passkey row carries its collection, and every lookup and access check matches collection and ID together (H3).
- **No internal fields leave the server:** a contract test asserts that no plugin response contains `hash`, `salt`, `sessions`, `apiKey`, `passkeyUserHandle` or `userHandle`, the one exception being `status`'s `signalUserId` for the signed-in owner (M1).
- **User verification is required** at registration and sign-in: a passkey always means the device plus biometrics or the device PIN.
- **Enumeration:** discoverable sign-in never names an account; all sign-in failures look the same and take similar time.
- **Account rules respected:** locked accounts, unverified accounts, the host's `beforeLogin` hooks, Payload's `access.admin`-style checks through the minted session.
- **Persistence attacks:** adding a passkey needs a fresh session or the password (4.1).
- **Rate limiting:** Payload has no IP limiter, and serverless has no shared memory. The `rateLimit` option is called on every endpoint with an action and a key (IP, user). The README:
  - shows Vercel WAF and Upstash examples;
  - explains that the IP comes from `x-forwarded-for` and can only be trusted behind a proxy that sets it.

  Built in:
  - per-user caps on stored passkeys (default 20) and outstanding challenges;
  - one outstanding sign-in challenge per browser;
  - a global cap on anonymous challenges (default 500);
  - pruning of expired challenges and uses on every challenge write;
  - a boot warning in production when `rateLimit` is left at its default (M2).
- **Logging:** `passkeys.registered`, `.removed`, `.renamed`, `.signed_in`, `.signed_in_while_locked`, `.sign_in_failed` (with reason), `.counter_regression`, `.unknown_credential`, `.reauth_required`. Each line carries the collection, user ID, credential ID prefix and AAGUID. Never challenges, signatures, public keys or emails.
- **Privacy (UK GDPR):** an IP address is personal data. `logging.ip` is `'truncated'` by default (/24 for IPv4, /48 for IPv6), with `'none'` and `'full'` as the alternatives, and no IP is logged on a successful sign-in. The README names the lawful basis (legitimate interest in security) and says retention is the host's log retention (L1).
- **Client bundle:** no server module reachable from client entry points (test-enforced), no secrets in client props.
- **Open redirect:** post-sign-in redirects are restricted to same-origin admin paths.
- **Recovery:** the password and forgot-password always remain. A Payload `config.bin` script, run in the host project as `pnpm payload passkeys:reset --collection users --email x`, removes a user's passkeys through the Local API for a locked-out site owner, and always empties their sessions too (M6).
- **Supply chain (L9):**
  - SimpleWebAuthn is pinned to exact versions and bumped by hand.
  - pnpm `minimumReleaseAge` is 7 days.
  - A test asserts that the `./client` entry's dependency graph contains only `@simplewebauthn/browser` and `@payloadcms/ui`.

## 7. Compatibility

- Peer dependencies: `payload`, `@payloadcms/ui` (`>=3.90.0 <4`), `react`, `react-dom`, `next`. `@payloadcms/next` is not needed in v1 (nothing imports it). Dependencies: the two SimpleWebAuthn packages only.
- `useAuth()` changed in 3.91 (`tokenExpirationMs` replaced by `authSession.expiresAt`); the plugin feature-detects both.
- `@payloadcms/ui` 3.x exports no router hooks, so `useRouter` and `useSearchParams` come from `next/navigation.js` in exactly one module (`src/components/shared/navigation.ts`); the v4 port changes that file. Everything else follows v4's import rules already.
- Postgres and SQLite hosts must run `payload migrate:create` and `payload migrate` after installing (the plugin adds three collections and two fields); the README says so, and the dev app ships example migrations to prove they generate cleanly. MongoDB needs nothing.
- Every host must run `payload generate:importmap` and `generate:types` after installing.
- Multiple auth collections: each configured collection gets its own endpoints and fields; `passkeys.user` is polymorphic when more than one is configured.

## 8. Copy and translations

All admin text goes through Payload's i18n (`config.i18n.translations` merged under a `passkeys` namespace), so hosts can override or translate it. English strings use UK spelling (The Digital Stride house style). Payload does not fall back to English for a missing plugin key, so the English strings are copied into every language Payload supports until real translations arrive.

## 9. Testing

- **Unit (Vitest):** option resolution, RP ID and host matching, redirect validation, AAGUID naming, counter policy, challenge record logic, error mapping.
- **Integration (Vitest + real Payload):** the dev app's config booted with `getPayload` on MongoDB (mongodb-memory-server), SQLite (file) and Postgres (service container in CI). Full ceremonies against the endpoints using a software authenticator built on WebCrypto (registration and assertion objects signed in the test), covering every rejection path: replayed, expired, cross-type, cross-browser and cross-user challenges; wrong origin; wrong RP ID; UV flag missing; unknown and deleted credentials; locked and unverified users; a throwing `beforeLogin` hook; duplicate credential IDs.
- **Contract (`mintSession`):** the minted cookie authenticates `/api/<users>/me`, refresh extends it, logout revokes it, "log out of all sessions" revokes it, a password change revokes it. Run for every supported Payload minor (CI matrix) and nightly against `payload@latest` and `payload@beta`.
- **End to end (Playwright, Chromium):** the dev app with a CDP virtual authenticator (`WebAuthn.addVirtualAuthenticator`, internal transport, UV on): enrol from the prompt, sign out, sign in with the button, rename, remove, preview-host hiding.
- **Static:** the client-import boundary test; `tsc --noEmit`; ESLint; a test that the built package's `exports` resolve.

## 10. Repository, build and release

- Layout from Payload's plugin template: `src/` (`index.ts`, `exports/client.ts`, `exports/rsc.ts`, `server/`, `components/`, `collections/`, `translations/`), `dev/` (a Next app with Mongo, SQLite and Postgres configs selected by env), `test/`.
- ESM only, built with swc and type declarations from tsc; `exports` for `.`, `./client`, `./rsc`; `sideEffects` set so CSS is kept.
- Changesets for versioning and the changelog; publishing is `npm publish` (npm ≥11.5.1, upgraded in the job), because npm documents OIDC trusted publishing for `npm publish` only.
- GitHub Actions: lint, types, unit, integration matrix (Payload minors × adapters), e2e, nightly latest/beta contract run; CodeQL; Dependabot (grouped, weekly).
- Release, hardened as in review L9:
  - npm **trusted publishing** from a protected `release` workflow (OIDC, no npm token stored), with provenance;
  - signed tags;
  - branch protection with required reviews and checks;
  - every GitHub Action pinned to a commit SHA;
  - `CODEOWNERS` on `.github/workflows/`;
  - `npm audit signatures` in CI;
  - npm and GitHub accounts protected by passkeys;
  - the README tells users how to verify provenance.
- `SECURITY.md` with GitHub private vulnerability reporting, a supported-versions table and a fix-before-disclose policy.
- An adversarial security review (separate reviewer, threat-model driven) before 1.0.0.

## 11. Phase 2: idle lock screen

Goal: a signed-in admin left idle is locked after 15 minutes (configurable), and unlocks with their passkey (fingerprint or device PIN) or, without one, their password, without losing what is on screen.

- **Lock is server-enforced by revoking the session.** An auth strategy cannot veto Payload's own JWT check, so an overlay alone would be theatre. On lock, the client calls `POST /passkeys/lock`, which removes the current `sid` from the user's sessions (the same write core's logout does) and expires the cookie. From then on every API call is anonymous until unlock.
- **Activity and timing:** the provider tracks pointer, key, scroll, focus and route changes; tabs share activity and lock state over `BroadcastChannel`; on `visibilitychange` and wake it compares wall-clock time, so a laptop opened after an hour locks before showing anything. Payload's own `tokenExpiration` remains the backstop when no tab is open.
- **Lock ticket (H2):** `/passkeys/lock` also sets an HttpOnly lock-ticket cookie. It is an HMAC, keyed from `payload.secret` and domain-separated, over `{ collection, userId, lockedAt, exp }`, where `exp` is the old session's expiry. The unlock endpoints accept only a valid ticket, so the server, not the client, knows who is locked.
- **The lock box** covers the admin with an opaque layer, makes the app `inert`, and offers two ways back:
  - **the passkey:** discoverable, with **empty `allowCredentials`**, so no credential IDs are disclosed. Unlock verify refuses a passkey that belongs to anyone but the ticket's user.
  - **the password:** a ticket-bound unlock endpoint that runs `payload.login()` with the ticket user's email fixed on the server, keeping Payload's lockout.

  Unlock mints a new session and the page carries on.
- **Across tabs (M8):** a tab drops its overlay only after its own `/me` call confirms a live session. `BroadcastChannel` messages are hints to re-check, never state.
- **What the lock does not do (M8):** it protects the server and every later request, not what is already rendered. The DOM behind the overlay, the router cache and local storage remain readable to someone with DevTools. The README says so plainly. The option `lock.clearOnLock: 'navigate-home'` moves to the dashboard before locking when the current view is sensitive (users, API keys). The plugin never stores form state in local storage while locked.
- **Autosave while locked:** requests fail as anonymous; the provider pauses Payload's autosave and form submission while locked where Payload allows, and otherwise surfaces the failure after unlock. To be designed in detail in the phase 2 plan, with tests on drafts with autosave.
- **Interplay with 3.91+ activity-aware sessions** (which refresh tokens on activity): the plugin uses its own activity tracker for locking, and the plan verifies the two don't fight.
- Options: `lock.enabled`, `lock.idleMinutes` (15), `lock.onHidden` (false), `lock.collections`, `lock.clearOnLock` (`'none'`).

## 12. Risks and open questions

| Risk | Mitigation |
|---|---|
| Payload changes the undocumented login helpers or the JWT claims | One adapter module, per-minor contract tests, nightly latest/beta run, a tested peer range |
| `beforeLogin`/`afterLogin` hooks behave differently outside `loginOperation` | Integration tests with throwing and mutating hooks; documented |
| Sign-in button and prompt layout shift between Payload minors | e2e screenshots per minor; minimal styling with Payload CSS variables |
| AAGUID list retirement | Vendored snapshot; names are display-only; FIDO C-MDS later |
| SimpleWebAuthn 14 requires Node 22 | Matches the supported range; documented |
| Password re-check helper for "fresh session" not exported | Resolved: re-auth is a real `payload.login()` (H1) |
| Hosts relying on `beforeOperation`/`afterOperation` for `login` (audit, geo rules) | Documented gap; `onSignIn` option (L8) |
| Hosts with `useSessions: false` can't use the plugin | Refused at config time with a clear message (D14); revisit if asked |
| npm organisation name not yet claimed | Release-plan step; fall back to `@thedigitalstride` if taken |
