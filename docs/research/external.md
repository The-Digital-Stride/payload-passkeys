# Passkey / passcode access for the Payload CMS 3 admin: external research

Prepared 2026-11-06 for the design of a reusable, open-source Payload CMS 3 plugin that adds passkey (WebAuthn) and passcode access to the admin panel. Every claim that could change carries a URL and a date (the page's own date, or "fetched 2026-11-06"). Items marked **uncertain** or **(fragile)** were not confirmed from a primary source or rest on undocumented behaviour.

**Contents**

1. WebAuthn / passkeys best practice now
2. Libraries
3. App-level PIN/passcode security
4. Session/lock-screen patterns
5. Existing Payload work
6. How other CMSs do it
7. Payload plugin authoring best practice (Payload 3)
8. Security pitfalls when bolting auth onto a framework
9. Recommendations for the plugin

### Headline findings

- **WebAuthn Level 3 became a W3C Recommendation on 25 August 2026**; Level 4 work has started. Conditional UI, BE/BS flags, the Signal API, related origins, `getClientCapabilities()` and AAGUID-without-attestation are now stable to build on.
- **Payload has no passkey, 2FA or PIN feature and no roadmap item for one.** The only passkey plugin (`payload-passkey`, Aug 2026) drags in Better Auth; `payload-totp` is the best structural model. Payload 3.90.0 (Sept 2026) added a JWT `authVersion` marker that silently rejects hand-made tokens, so a plugin must mint sessions with Payload's own helpers.
- **Use `@simplewebauthn/server` + `/browser` v14.** Oslo, Lucia, `@github/webauthn-json` and `webauthn-p256` are deprecated or archived; Auth.js passkeys are experimental and pinned to SimpleWebAuthn v9.
- **A server-checked short PIN is a password under NIST SP 800-63B rev 4 (final, July 2025)** and must not be a login factor; it is acceptable only to re-open an existing session, with about 5 attempts, an HMAC pepper, scrypt, and a device binding. Platform passkeys with `userVerification: 'required'` already give "device + biometric or passcode" with hardware backing, so the app PIN is a fallback, not the headline.
- **A lock screen is theatre unless the server enforces it**: keep per-session state (`lockedAt`, `authTime`, `stepUpUntil`) keyed by Payload's `sid` and refuse in access functions/hooks, not in Next.js middleware (CVE-2025-29927) or a React overlay.
- **`vercel.app` is on the Public Suffix List**, so every Vercel preview is its own RP ID; passkeys need a stable domain (production or a custom preview domain) and the plugin should fall back to password login elsewhere.
- **The community AAGUID list is being retired** (empty from 6 Jan 2027); vendor a snapshot and plan for FIDO's consumer MDS.
- Craft 5 and Statamic 6 are the CMS models (native passkeys, recovery codes, 5–15 min elevated sessions); their recent CVEs (client-supplied challenges, elevated-session bypass) and WordPress Two Factor's REST bypass are the pitfalls to design against.

---

## 1. WebAuthn / passkeys best practice now

### 1.1 Spec status

- **WebAuthn Level 3 is a W3C Recommendation as of 25 August 2026** (`https://www.w3.org/TR/2026/REC-webauthn-3-20260825/`; status line "W3C Recommendation, 25 August 2026", fetched 2026-11-06 from https://www.w3.org/TR/webauthn-3/). It supersedes Level 2 (Recommendation, 8 April 2021). The FIDO Alliance announced it on 31 August 2026 and says "Work on WebAuthn Level 4 is already underway" (https://fidoalliance.org/webauthn-level-3-is-now-a-w3c-recommendation/, 2026-08-31). No substantive changes since the CR snapshot of 26 May 2026.
- passkeys.dev's spec reference page still listed Level 2 as "Current" and Level 3 as "Next" when fetched (page last updated 31 Oct 2025; https://passkeys.dev/docs/reference/specs/); it is simply behind. CTAP 2.2 is the current authenticator protocol (FIDO PS 2025-07-14), CTAP 2.3 in development.
- What L3 standardises (all already shipped in browsers against drafts, per the FIDO announcement and https://startwithidentity.com/blog/2026-08-31-webauthn-level-3-becomes-a-w3c-recommendation/, 2026-08-31): conditional mediation for get (autofill) and create (passkey upgrades); BE/BS backup flags; the Signal API; AAGUID conveyed without attestation; client hints; Related Origin Requests; the PRF extension; JSON (de)serialisation helpers (`parseCreationOptionsFromJSON`, `parseRequestOptionsFromJSON`, `toJSON()`); `getClientCapabilities()`; cross-origin iframe use. Also: `pubKeyCredParams` SHOULD include -8 (EdDSA), -7 (ES256) and -257 (RS256), and the RFC 9864 "fully-specified" identifiers (-9, -51, -52, -19) are NOT RECOMMENDED in `pubKeyCredParams` (spec §5.4, fetched 2026-11-06).

Practical consequence: the plugin can cite L3 as a stable normative reference and should feature-detect with `getClientCapabilities()` rather than UA-sniff.

### 1.2 FIDO Alliance / passkeys.dev / Google guidance on options

From passkeys.dev "Bootstrapping" (https://passkeys.dev/docs/use-cases/bootstrapping/, fetched 2026-11-06) and Google's server guides (https://developers.google.com/identity/passkeys/developer-guides/server-registration and `/server-authentication`, undated, fetched 2026-11-06):

| Option | Recommended | Why |
|---|---|---|
| `authenticatorSelection.residentKey` | `"required"` (plus `requireResidentKey: true` for old clients) | Makes the credential discoverable, i.e. a passkey. passkeys.dev: "passkeys must always be discoverable credentials". |
| `authenticatorSelection.userVerification` | `"preferred"` for consumer sign-in; `"required"` where UV is the second factor (see 1.5) | `preferred` avoids hard failures on devices with no biometric/PIN; the server still reads the UV flag. |
| `attestation` | `"none"` (default) or `"indirect"` | Other values add consent prompts and abandonment. AAGUID still arrives (see 1.12). |
| `excludeCredentials` | All of the user's existing credential IDs (+ transports) | Stops the same authenticator registering twice (spec §13.4.6 also says use `excludeCredentials` and `user.id` for this). |
| `pubKeyCredParams` | ES256 (-7), RS256 (-257); add EdDSA (-8) | Spec §5.4 recommendation; RS256 is still needed for older Windows Hello. |
| `authenticatorAttachment` | Leave unset for registration (passkeys.dev); Google's sample sets `"platform"` | Unset lets the user choose a security key; after a sign-in with `authenticatorAttachment === "cross-platform"`, offer to create a local passkey. |
| `extensions.credProps` | `true` | Tells you whether the credential actually became discoverable (`rk`). |
| `user.id` | 64 random bytes, stored on the account; never e-mail or username, not even hashed unsalted | Spec §14.6.1 (MUST NOT contain PII; RECOMMENDED 64 random bytes). |
| `user.name` / `displayName` | e-mail / friendly name | Shown in the picker; update via `signalCurrentUserDetails` if they change. |
| `timeout` | 300 000 ms default; recommended range 300 000–600 000 ms | Spec §15.1. Google: longer for hybrid flows. |

Offer passkey creation only after a strong sign-in (passkeys.dev), and tell the user "anyone who can unlock this device can access the account".

### 1.3 Conditional UI (autofill) and `getClientCapabilities()`

- Conditional mediation ("Conditional Get", autofill UI): mark the username field `autocomplete="username webauthn"`, and on page load call `navigator.credentials.get({ mediation: 'conditional', publicKey: { challenge, rpId, allowCredentials: [], userVerification: 'preferred' }, signal })`. The promise stays pending with no UI until the user picks a passkey from the autofill dropdown; if they pick a password instead it never resolves, so the password flow proceeds normally. Cancel the pending request with an `AbortController` before making any other WebAuthn call (a modal `get()` for a "Sign in with a passkey" button) or when leaving the page. Errors: `NotAllowedError` (user cancelled / none chosen), `AbortError` (you aborted). (web.dev "Sign in with a passkey through form autofill", https://web.dev/articles/passkey-form-autofill, fetched 2026-11-06; Chrome docs https://developer.chrome.com/docs/identity/webauthn-conditional-ui.)
- Feature detection: `PublicKeyCredential.getClientCapabilities()` resolves to booleans keyed `conditionalCreate`, `conditionalGet` (same as `isConditionalMediationAvailable()`), `hybridTransport`, `passkeyPlatformAuthenticator`, `userVerifyingPlatformAuthenticator`, `relatedOrigins`, `signalAllAcceptedCredentials`, `signalCurrentUserDetails`, `signalUnknownCredential`, and `extension:<id>` (e.g. `extension:prf`). `true` = supported now, `false` = not, key absent = unknown. Baseline "Newly available" since February 2025, secure contexts only (MDN, last modified 27 Oct 2026, https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/getClientCapabilities_static). Keep `isUserVerifyingPlatformAuthenticatorAvailable()` / `isConditionalMediationAvailable()` as fallbacks for browsers without `getClientCapabilities`.
- Conditional Create ("passkey upgrades"): `navigator.credentials.create({ mediation: 'conditional', publicKey })` right after a password sign-in whose password the browser's manager autofilled, same username; no modal, silent success or silent no-op. Detect with `capabilities.conditionalCreate`. Chrome desktop 136+, Android 142 (provider-dependent), Safari 18 / iOS 18+ (https://developer.chrome.com/docs/identity/webauthn-conditional-create and passkeys.dev device support, both fetched 2026-11-06). Server-side difference: the UP flag may be `false` for a conditionally created credential (spec §7.1: "If options.mediation is not set to conditional, verify that the UP bit ... is set"; Google registration guide says the same). Users can disable automatic upgrades in Chrome's password-manager settings. Nice-to-have for a CMS admin, not v1.
- Device support snapshot (passkeys.dev/device-support, last updated 21 Sep 2026): synced passkeys on Android 9+, ChromeOS 129+, iOS 16+, macOS 13+; Windows stores passkeys in Windows Hello (device-bound unless a third-party manager is used, 25H2+ for third-party managers); Linux has no native platform passkeys (browser extensions only). Conditional UI: Chrome 108+, Edge 122+, Safari 16.1+, Firefox 122+/129+ depending on platform. Related origins: Chrome/Edge 128+, Safari on macOS 15 / iOS 18+, Firefox 152+. Hints: Chrome/Edge 128+, not iOS.

### 1.4 Signal API

Three static methods on `PublicKeyCredential` (spec §5.1.10; Chrome docs https://developer.chrome.com/docs/identity/webauthn-signal-api, published 12 Nov 2024, updated 29 Nov 2024; MDN capability keys above):

| Method | Params | When the RP calls it | Effect |
|---|---|---|---|
| `signalUnknownCredential({ rpId, credentialId })` | credential the server did not recognise | after a sign-in attempt returns "unknown credential" (e.g. 404) | provider deletes/hides that one passkey; safe while signed out because it reveals nothing about the account |
| `signalAllAcceptedCredentials({ rpId, userId, allAcceptedCredentialIds })` | full list of valid credential IDs for `userId` | after the user deletes a passkey, and on every sign-in / credentials page view | provider hides passkeys not in the list (restorable by a later call). **Only call when signed in**; an empty list hides everything. |
| `signalCurrentUserDetails({ rpId, userId, name, displayName })` | new name/displayName | when the user changes e-mail/name, and on sign-in | provider updates the passkey's labels (Google Password Manager keeps a user's manual edit) |

Support: Chrome/Edge 132+ (all three), Safari listed as 26 in some badges but "not yet implemented" in the text (verify), Firefox none. Feature-detect each method; `rpId` must be valid for the calling origin (spec §5.1.10.1 asynchronous RP ID validation, which also hides timing so sites can't probe credential availability). Keep a manual "remove it from your device too" hint as fallback.

### 1.5 User verification: `required` vs `preferred`

- Spec semantics (web.dev "User verification", https://web.dev/articles/webauthn-user-verification, fetched 2026-11-06): `preferred` (default) performs UV when the device can and skips it otherwise; the UV flag reports what happened. `required` makes the client fail locally when UV cannot be done; on a Mac without Touch ID the user types the macOS password. `discouraged` asks the client to skip it, but authenticators may still verify.
- On Windows 11 22H2+ Windows Hello always requires at least a PIN, so `preferred` and `required` behave the same there (https://passkeys.dev/docs/reference/windows/).
- Guidance: passkeys.dev, Google and web.dev all default to `preferred` for consumer sign-in to cut abandonment; `required` when UV is itself the second factor (which is exactly the "biometric or device passcode" product promise). **Always check the UV flag server-side regardless** (spec §7.2 "If the Relying Party requires user verification ... verify that the UV bit ... is set"; SimpleWebAuthn exposes `requireUserVerification`). web.dev also notes: don't add a second factor on top of a passkey; it already resists phishing.
- Recommendation for an admin plugin: request `required` and enforce the UV flag. Admins are few and can be told to set up a device PIN/biometric; a passkey without UV is "possession only" and should not unlock a CMS by itself.

### 1.6 Attestation

- `none` is the default and the recommendation for consumer and small-team use (passkeys.dev; Google). With `none`, the attestation statement is replaced by `{ fmt: "none", attStmt: {} }` (spec §8.7) but the authenticator data still carries the AAGUID; L3 explicitly lets credential managers "share their identifier without attestation" (FIDO announcement). `direct`/`enterprise` matter only when policy must prove hardware (e.g. "only YubiKeys"), which needs FIDO MDS trust chains and adds consent prompts. Spec §13.4.4 (Attestation Limitations) and MDN both warn RPs not to maintain authenticator allowlists in general.

### 1.7 Resident / discoverable credentials; synced vs device-bound; BE/BS flags

- A passkey = a discoverable (resident) credential. Synced passkey: backed up by the provider (iCloud Keychain, Google Password Manager, 1Password...). Device-bound passkey: lives on one authenticator (security keys; Windows Hello without a third-party manager) (https://passkeys.dev/docs/reference/terms/).
- Authenticator data flags BE (backup eligible, fixed at creation) and BS (backup state, may change): 0/0 single-device, 1/0 multi-device not currently backed up, 1/1 backed up; 0/1 invalid (spec §6.1.3). RP steps (spec §7.1/§7.2): if BE is 0, verify BS is 0; store both; on each assertion compare `currentBe` with the stored `backupEligible` (must not change); apply policy. "It is RECOMMENDED that Relying Parties store the most recent value of these flags." Suggested uses: BE=0 means "not resilient to single device loss" so SHOULD ensure extra authenticators or recovery; BS 0→1 may prompt "remove your password"; BS 1→0 SHOULD prompt the user to check other factors / add another credential.
- SimpleWebAuthn surfaces these as `credentialDeviceType: 'singleDevice' | 'multiDevice'` and `credentialBackedUp` (see section 2).

### 1.8 Signature counter with synced passkeys

- Spec §7.2 (L3, fetched 2026-11-06): "If authData.signCount is nonzero or credentialRecord.signCount is nonzero, then ... If authData.signCount is greater than credentialRecord.signCount: The signature counter is valid. less than or equal to ...: This is a signal, but not proof, that the authenticator may be cloned ... Whether the Relying Party updates credentialRecord.signCount ..., or fails the authentication ceremony or not, is Relying Party-specific." §6.1.1: authenticators without a counter leave it at zero.
- In practice iCloud Keychain, Google Password Manager and Windows Hello synced passkeys always return 0 (https://uzyn.com/2025/passkey-has-a-theft-detection-feature-but-big-tech-broke-it/, 2025; Adam Langley 2023 https://www.imperialviolet.org/2023/08/05/signature-counters.html: "I've never heard of a signature counter actually being used to catch an attack"). Hard-failing on a non-increasing counter locks out most consumer passkeys.
- Recommendation: store `counter`; if both are 0 skip; if the stored or new value is non-zero and the new value is not greater, **log a warning and flag the credential** (for a single-admin CMS, optionally fail closed only for credentials with BE=0, i.e. security keys, which do have real counters). Never update a stored counter downwards.

### 1.9 RP ID: subdomains, localhost, Vercel previews, custom domains

- Rule (spec §5.1.3/§4, fetched 2026-11-06): the RP ID defaults to the caller origin's effective domain and "MAY be overridden by the caller, as long as the caller-specified RP ID value is a registrable domain suffix of or is equal to the caller's origin's effective domain." It has no scheme or port. So a passkey with RP ID `example.com` works on `example.com`, `cms.example.com`, `www.example.com` (any port); RP ID `cms.example.com` works only there. A public suffix (`com`, `co.uk`, `vercel.app`) is refused with `SecurityError`. Changing the RP ID later breaks every existing passkey unless the new one is a parent of the old (Corbado, https://docs.corbado.com/helpful-guides/passkeys/relying-party-id).
- **`vercel.app` is on the Public Suffix List** (private section, "Vercel, Inc", line ~16356 of https://publicsuffix.org/list/public_suffix_list.dat, fetched 2026-11-06), as are `netlify.app` and `pages.dev`. Vercel URLs are `<project>-<hash>-<scope>.vercel.app` (per commit), `<project>-git-<branch>-<scope>.vercel.app` (per branch) and `<project>.vercel.app` (https://vercel.com/docs/deployments/generated-urls, last updated 2026-09-08). Each is its own registrable domain, so each preview deployment is its own RP ID and passkeys made on one never work on another. Options: (a) don't offer passkeys on previews (fall back to password), gating on `VERCEL_ENV !== 'production'` or on the host not matching the configured RP ID; (b) give the preview environment a stable custom domain (`preview.example.com`) and use RP ID `example.com` so production and preview share passkeys; Vercel's "Preview Deployment Suffix" (Pro/Enterprise) replaces `vercel.app` with a custom suffix, which would make `*.preview.example.com` previews able to use RP ID `example.com`; (c) Related Origin Requests do not help here because they are capped at ~5 labels and the preview hosts are all under one public suffix anyway.
- Expected origin(s) must be checked separately from the RP ID: `clientDataJSON.origin` must equal one of the configured origins (scheme + host + port). Libraries accept arrays for both (SimpleWebAuthn `expectedOrigin: string[]`, `expectedRPID: string[]`).
- `localhost`: `http://localhost` and `http://127.0.0.1` are secure contexts (W3C Secure Contexts §3.1, loopback CIDR and `localhost` names), so WebAuthn works in dev with RP ID `localhost`; those credentials never transfer anywhere else. Testing on a phone needs a real HTTPS origin (ngrok/cloudflared) and the tunnel's host as RP ID (https://www.corbado.com/blog/test-passkeys-localhost-ngrok). Note Payload's own cookie `secure` cannot be on at `http://localhost` either, so the plugin should derive its RP ID / origin from `serverURL` or an explicit option and from the request `Host`/`Origin` header in dev.
- Related Origin Requests (https://passkeys.dev/docs/advanced/related-origins/, fetched 2026-11-06): host `https://<rpid>/.well-known/webauthn` as `application/json` `{ "origins": [ ... ] }`, omit origins already covered by the RP ID, max 5 unique labels (the name before the eTLD), detect with `capabilities.relatedOrigins`. Intended for ccTLD/brand variants, not previews. A plugin could expose a `relatedOrigins` option that serves this file, but it is a v2 feature.

### 1.10 Challenge storage, expiry, replay protection

- Spec §13.4.3: challenges "MUST be randomly generated by Relying Parties in an environment they trust (e.g., on the server-side), and the returned challenge value in the client's response MUST match what was generated. ... the Relying Party SHOULD store the challenge temporarily until the operation is complete. Challenges SHOULD be valid for a duration similar to the upper limit of the recommended range and default for a WebAuthn ceremony timeout [5–10 min] ... Challenges SHOULD therefore be at least 16 bytes long." SimpleWebAuthn uses 32 bytes (Google authentication guide).
- Replay protection is the challenge: one per ceremony, single use, deleted on success *and* failure, expiry ≤ ceremony timeout, bound to the user (or to an anonymous pre-session for usernameless sign-in) and to the ceremony type (`clientDataJSON.type` is `webauthn.create` / `webauthn.get`, which libraries check). Also verify `origin`, `rpIdHash`, flags, signature, and that a registration's credential ID is not already registered to any user (spec §7.1 step 26; Google).
- Storage models for a stateless/serverless host: (1) a DB collection `webauthn-challenges` (challenge, user, type, expiresAt, TTL index on Mongo / cron delete on SQL) deleted atomically on use; (2) a signed, HttpOnly, short-lived cookie `__Host-pk-challenge` carrying `{challenge, userId?, type, exp}` under an HMAC with `PAYLOAD_SECRET`, which is stateless but makes single-use harder to guarantee (a replay within the TTL window is possible unless you also record used challenges). (1) is the safer default and works on every Payload DB adapter via the Local API.

### 1.11 Account recovery and lost devices

- Spec §13.4.6: losing an authenticator "means losing all credentials bound to the lost authenticator, which could lock the user out ... Relying Parties SHOULD allow and encourage users to register multiple credentials to the same user account." §6.1.3: for BE=0 credentials "Relying Parties SHOULD ensure that each user account has additional authenticators registered and/or an account recovery process in place."
- FIDO's own position: a service needs a secure recovery process, and multiple authenticators per user reduce how often it is needed (FIDO Alliance; Yubico in FreeIPA issue #9576: no vendor has "an optimal solution for every scenario", two or more registered devices is the safest).
- For a CMS admin plugin the realistic recovery ladder is: synced passkeys survive device loss by design; a second passkey (phone + laptop, or a security key); the existing password + e-mail reset (Payload's `forgot-password`) as long as the plugin doesn't disable the local strategy; one-time recovery codes (NIST look-up secrets, see section 3) if passwords are disabled; and a server-side escape hatch (another admin can remove a user's passkeys in the admin UI; a CLI/script using the Local API can clear `passkeys` for a user, or an env flag can temporarily re-enable password login). Never let the only admin's last passkey be removable without a confirmation that names what remains.

### 1.12 Credential naming and management UX; AAGUIDs

- Store per credential: credential ID (primary key), COSE public key, counter, transports, BE/BS, AAGUID, created at, last used at, optional user-given name (Google registration guide). Resolve the provider name and icon **at display time** from the AAGUID; don't bake names into the record (community wiki "RP Fallback", fetched 2026-11-06).
- **The community `passkeydeveloper/passkey-authenticator-aaguids` list is being retired**: no new submissions from 1 Nov 2026, both JSON files return `{}` from 6 Jan 2027, repository archived 6 Jul 2027 (README, fetched 2026-11-06). The replacement is FIDO's Metadata Service, which now has a consumer-passkey ("C-MDS") entry type with AAGUID, localised names and dark/light SVG logos (wiki "FIDO MDS Migration", edited 18 Oct 2026). Guidance from the wiki: persist the AAGUID; keep a local snapshot and refresh no more than once per 24 h (MDS returns 429 otherwise); treat missing or all-zero AAGUID (`00000000-0000-0000-0000-000000000000`) as unknown and show a generic label such as "Other credential manager (name unknown)" with a generic passkey icon; names/icons are display-only, never policy. The AAGUID records the manager that *created* the passkey, not where it lives now. For the plugin: ship a small vendored snapshot (Apple, Google, Microsoft, 1Password, Bitwarden, Dashlane, Proton, Samsung, Chrome on Mac, etc.) and allow the host to override/extend it; don't fetch at runtime in v1.
- FIDO/Passkey Central design guidelines (https://www.passkeycentral.org/design-guidelines/, redirected from fidoalliance.org/ux-guidelines, 2024 research cycle, fetched 2026-11-06) and Google's guide agree on: use the word "passkey" and the passkey icon; list each passkey with provider name/icon, creation date, last-used date, and a user-editable name; allow rename and delete; offer "Create a passkey" right after a non-passkey sign-in and after a cross-device sign-in; show an opt-in explanation; confirm before removing the last passkey.

### 1.13 Cross-device (hybrid / QR) flows

- "Cross-Device Authentication" (CDA) uses CTAP "hybrid" transport (formerly caBLE): the browser shows a QR code encoding a one-time session; the phone scans it, a Bluetooth LE proximity check confirms the devices are near each other, and the actual messages go over an internet tunnel; the private key never leaves the phone (https://passkeys.dev/docs/reference/terms/; https://www.corbado.com/glossary/cda). Client support: Android 9+, ChromeOS 108+, iOS 16+, macOS 13+, Windows 23H2+; authenticator side Android 9+ and iOS 16+ (passkeys.dev device support, 2026-09-21).
- RP implications: it is automatic when `allowCredentials` is empty or the listed credential has transport `hybrid`/`internal`; `hints: ['client-device']` can de-emphasise QR in the browser UI but Chrome ignores `transports: ['internal']` as a suppressor. After a hybrid sign-in (`authenticatorAttachment === 'cross-platform'`), offer to create a passkey on the current device. Need Bluetooth on both devices; a reason to keep password fallback on shared/locked-down machines.

---

## 2. Libraries

Research date: 2026-11-06. Download counts are npm's "last week" API (2026-10-29 to 2026-11-04, `https://api.npmjs.org/downloads/point/last-week/<pkg>`). Versions, dates, licences, engines and dependencies come from `npm view <pkg>` on 2026-11-06 unless another source is given. SimpleWebAuthn's signatures were read from the published `.d.ts` files in the 14.0.3 / 14.0.0 tarballs (`npm pack`), not from memory.

### 2.1 At a glance

| Library | Latest (date) | Weekly downloads | Licence | Status (fetched 2026-11-06) | Runtime |
|---|---|---|---|---|---|
| `@simplewebauthn/server` | 14.0.3 (2026-09-25) | 9.69 M | MIT | Active: last commits 2026-10-28 (TPM parsing, Android Key hardening), repo pushed 2026-11-06 | WebCrypto (`globalThis.crypto`); Node, Deno, Bun, CF Workers |
| `@simplewebauthn/browser` | 14.0.0 (2026-09-02) | 9.84 M | MIT | Active (same repo) | Browser, zero deps |
| `@simplewebauthn/types` | 12.0.0 | 1.12 M (legacy installs) | MIT | **Deprecated** on npm; types folded into `/browser` and `/server` in v13 | n/a |
| `@passwordless-id/webauthn` | 2.4.1 (2026-10-06) | 88 k | MIT | Maintained, mostly dependabot merges in Oct–Nov 2026; one org | Browser + server, dependency-free, Node 19+ / WebCrypto |
| `@oslojs/webauthn` | 1.0.0 (2024-09-19) | 122 k | MIT | **Deprecated 2026-07-29** (see 2.4); repo last pushed 2024-09-22 | Runtime-agnostic, no attestation verification |
| `@github/webauthn-json` | 2.1.1 (2023-01-31) | 150 k | MIT | **Deprecated, repo archived** (README: use native browser JSON methods) | Browser only |
| `@hexagon/webauthn` | 0.9.14 (last modified 2022-05-20) | 21 | MIT | **Deprecated**, dead | — |
| `webauthn-p256` (wevm) | 0.0.10 (2024-08-13) | 155 k | MIT | **Repo archived** 2024-11-07; superseded by `ox`'s WebAuthn modules | P-256 signing utilities only |
| `ox` (wevm) | 1.8.13 (2026-11-04) | 15.2 M | MIT | Active; crypto toolkit for Ethereum (viem) | Not a WebAuthn RP library |
| `@better-auth/passkey` | 1.7.18 (2026-11-05) | 3.09 M | MIT | Very active (several releases a week) | Wraps SimpleWebAuthn `^13.3.2` / `^13.3.0` |
| `@auth/core` passkey provider | 0.41.3 (2026-07-20) | 6.69 M (`@auth/core`) | ISC | **Experimental**; peer deps `@simplewebauthn/server ^9.0.2`, `/browser ^9.0.1` | Node ≥ 20 |
| `lucia` | 3.2.2 | 683 k | MIT | **Deprecated** (March 2025); now a guide | — |

### 2.2 SimpleWebAuthn (`@simplewebauthn/server` + `@simplewebauthn/browser`)

Maintainer: Matthew Miller (MasterKale, npm `iamkale`, sole npm maintainer). Repo: https://github.com/MasterKale/SimpleWebAuthn (2,386 stars, 14 open issues, not archived; fetched 2026-11-06). Docs: https://simplewebauthn.dev/docs/packages/server. Changelog: https://github.com/MasterKale/SimpleWebAuthn/blob/master/CHANGELOG.md.

**Release history (npm `time`, fetched 2026-11-06):**

| Version | Date | Headline (from CHANGELOG) |
|---|---|---|
| 10.0.0 | 2024-04-12 | Node ≥ 20; credential IDs become base64url strings everywhere; `rpID` required in `generateAuthenticationOptions()`; random `userID` (now `Uint8Array`) if omitted |
| 11.0.0 | 2024-10-13 | `startRegistration({ optionsJSON, useAutoRegister })` / `startAuthentication({ optionsJSON, useBrowserAutofill, verifyBrowserAutofillInput })` take one object (breaking); `AuthenticatorDevice` → `WebAuthnCredential` `{ id, publicKey, counter, transports }`; verify takes `credential` instead of `authenticator`; `requireUserPresence` option; AAGUID checked against cert extension |
| 12.0.0 | 2024-11-25 | Published to JSR; drops `deno.land/x`; otherwise identical to v11 |
| 13.0.0 | 2024-12-09 | `@simplewebauthn/types` retired, types now exported from `/browser` and `/server`; `preferredAuthenticatorType` (`'securityKey' \| 'localDevice' \| 'remoteDevice'`) → WebAuthn `hints`; `attestationType: 'indirect'` removed |
| 13.1.x | 2025-01-13 → 2025-07-05 | Dropped `cross-fetch` (punycode warning); warns on pre-v11 call shape |
| 13.2.x | 2025-09-15 → 2026-02-21 | Stricter return types; SafetyNet CTS check can be disabled; build provenance via GitHub Actions |
| 13.3.0–13.3.3 | 2026-03-10 → 2026-08-26 | `verifyMDSBlob()`; **security fix (CVSS v4 2.0)**: self-signed roots in `x5c` could bypass RP trust anchors; new FIDO MDS trust anchor |
| 14.0.0 | 2026-09-02 | **ML-DSA-44/65/87 (post-quantum) passkeys** where the runtime supports them; browser `sendSignal()`, `browserSupportsPasskeys()`, `getBrowserCapabilities()`; `expectedTopOrigin`; **minimum runtime Node 22 LTS / Deno 2.4** (breaking) |
| 14.0.1 | 2026-09-05 | PQC attestation statement verification |
| 14.0.2 | 2026-09-13 | **Security fix (CVSS v3 5.4 and 6.3)**: CRL processing only for CRLs chaining to an RP-chosen trust anchor |
| 14.0.3 | 2026-09-25 | PQC support checks evaluated lazily (no Node PQC warnings unless used) |

Corrections to the brief's assumptions (verified 2026-11-06):

- **v13 did not drop CommonJS.** Both 14.x packages still ship dual builds: `exports: { ".": { "import": "./esm/index.js", "require": "./script/index.js" } }` (server also exports `./helpers`).
- **Node requirement is ambiguous.** The v14 CHANGELOG says "Minimum runtimes are Node LTS 22.x", but `server@14.0.3`'s `package.json` still says `engines.node: ">=20.0.0"`. Treat Node 22 as the real floor for v14 (flag: uncertain whether 20 merely works or is tested). If a plugin must support Node 20, pin `^13.3.3`.
- `@simplewebauthn/types` was retired in v13.0.0 (2024-12) and is now marked deprecated on npm; import types from `@simplewebauthn/server` and `@simplewebauthn/browser`.

**Runtime.** The server uses WebCrypto via `globalThis.crypto` (`helpers/iso/isoCrypto/getWebCrypto.js`), not `node:crypto`, so it runs on Node, Deno, Bun and Workers. Node-only is fine for Payload.

**Server dependencies (`server@14.0.3`):** `@peculiar/x509 ^2.1.0` (which pulls `tsyringe`, `@peculiar/utils` and several `@peculiar/asn1-*` v3 packages), `@peculiar/asn1-ecc`, `-rsa`, `-x509`, `-schema`, `-android`, `-x509-post-quantum`, `@levischuck/tiny-cbor ^0.2.2`, `@hexagon/base64 ^1.1.27`, `reflect-metadata ^0.2.2`. Unpacked size about 248 kB for the server package itself, before dependencies. Server-only, so bundle size doesn't matter for the admin.

**Browser package (`browser@14.0.0`):** no dependencies. All ESM `.js` comes to about 40 kB raw and **about 8.5 kB gzipped** (measured 2026-11-06 with comments included, so the minified size is smaller).

**Server API (from the 14.0.3 `.d.ts`):**

```ts
generateRegistrationOptions({
  rpName: string; rpID: string; userName: string;
  userID?: Uint8Array; challenge?: string | Uint8Array; userDisplayName?: string; timeout?: number;
  attestationType?: 'direct' | 'enterprise' | 'none';
  excludeCredentials?: { id: Base64URLString; transports?: string[] }[];
  authenticatorSelection?: AuthenticatorSelectionCriteria; // residentKey, userVerification, authenticatorAttachment
  extensions?: AuthenticationExtensionsClientInputs;
  supportedAlgorithmIDs?: number[];
  preferredAuthenticatorType?: 'securityKey' | 'localDevice' | 'remoteDevice';
}): Promise<PublicKeyCredentialCreationOptionsJSON>

verifyRegistrationResponse({
  response: RegistrationResponseJSON;
  expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>);
  expectedOrigin: string | string[];
  expectedRPID?: string | string[];
  expectedType?: string | string[];
  requireUserPresence?: boolean; requireUserVerification?: boolean;
  supportedAlgorithmIDs?: number[]; attestationSafetyNetEnforceCTSCheck?: boolean;
}) → { verified: true, registrationInfo: {
  fmt, aaguid: string, credential: WebAuthnCredential /* { id, publicKey: Uint8Array, counter, transports? } */,
  credentialType: 'public-key', attestationObject: Uint8Array, userVerified: boolean,
  credentialDeviceType: 'singleDevice' | 'multiDevice', credentialBackedUp: boolean,
  origin: string, rpID?: string, authenticatorExtensionResults?
}} | { verified: false }

generateAuthenticationOptions({
  rpID: string; allowCredentials?: { id; transports? }[]; challenge?; timeout?;
  userVerification?: 'required' | 'preferred' | 'discouraged'; extensions?;
}): Promise<PublicKeyCredentialRequestOptionsJSON>

verifyAuthenticationResponse({
  response: AuthenticationResponseJSON;
  expectedChallenge: string | ((c: string) => boolean | Promise<boolean>);
  expectedOrigin: string | string[]; expectedRPID: string | string[];
  credential: WebAuthnCredential;
  expectedType?; expectedTopOrigin?: string | string[];
  requireUserVerification?: boolean; advancedFIDOConfig?: { userVerification? };
}) → { verified, authenticationInfo: {
  credentialID, newCounter, userVerified, credentialDeviceType, credentialBackedUp,
  origin, rpID, authenticatorExtensionResults?
}}
```

Also exported: `MetadataService` (FIDO MDS3, `initialize({ … logger })` in v14), `SettingsService` (root certs per attestation format), `verifyMDSBlob()` (13.3.0+), error classes.

- `requireUserVerification` defaults to `false` on both verify calls. The docs advise `userVerification: 'required'` on options plus `requireUserVerification: true` on verify where you need MFA-grade assurance (https://simplewebauthn.dev/docs/advanced/passkeys, fetched 2026-11-06). **A PIN-or-passkey unlock should require UV**, otherwise a security key without a PIN counts as a touch only.
- `expectedOrigin` and `expectedRPID` take arrays, which covers the localhost, preview and production origins in one config. Note that on Vercel, preview hosts (`*.vercel.app`) are a different RP ID from the production domain, so passkeys registered on production won't work on previews.
- `expectedChallenge` takes a function, so a plugin can check a challenge stored server-side (or in an HMAC'd cookie) and consume it once.

**Counters.** The 14.0.3 `verifyAuthenticationResponse.js` throws only when `(counter > 0 || credential.counter > 0) && counter <= credential.counter`. Synced passkeys (iCloud Keychain, Google Password Manager) normally always report 0, so they pass and clone detection is impossible for them; the docs say this explicitly for Touch ID. Store `newCounter` after every success anyway: hardware keys increment it, and Craft's critical replay bug (section 6.5) came partly from not saving it.

**Browser API (14.0.0 `index.d.ts`):** `startRegistration({ optionsJSON, useAutoRegister? })`, `startAuthentication({ optionsJSON, useBrowserAutofill?, verifyBrowserAutofillInput? })`, `sendSignal(opts)` (new in v14: `unknownCredential { rpID, credentialID }`, `allAcceptedCredentials { rpID, userID, allAcceptedCredentialIDs }`, `currentUserDetails { rpID, userID, userName, userDisplayName? }`; fire and forget), `browserSupportsWebAuthn()`, `browserSupportsPasskeys()` (v14), `platformAuthenticatorIsAvailable()`, `browserSupportsWebAuthnAutofill()`, `getBrowserCapabilities()` (v14, returns `'supported' | 'unsupported' | 'unknown'` per capability), `WebAuthnAbortService`, `WebAuthnError`, and base64url helpers.

**`PublicKeyCredential.parseCreationOptionsFromJSON`:** the browser package declares it in its DOM types, but `startRegistration.js` still decodes the options itself with `base64URLStringToBuffer`, so it works in browsers without the native JSON methods. All major stable browsers have had `parseCreationOptionsFromJSON`, `parseRequestOptionsFromJSON` and `toJSON()` since March 2025, per GitHub's deprecation note (https://github.com/github/webauthn-json, archived; fetched 2026-11-06).

**Attestation / MDS:** full support: packed, TPM, Android Key, Android SafetyNet, FIDO U2F, Apple and none, plus PQC statements in 14.0.1. Settings and Metadata services; `attestationType: 'direct' | 'enterprise' | 'none'`. A CMS plugin should use `'none'`, since synced passkeys give no attestation (passwordless.id docs, below).

### 2.3 `@passwordless-id/webauthn`

Repo https://github.com/passwordless-id/webauthn (618 stars, 0 open issues, pushed 2026-11-04). Versions: 2.3.0 2025-03-16, 2.3.5 2026-02-15, 2.4.0 2026-05-15 (removed the `browser` field from `package.json`), 2.4.1 2026-10-06. ESM only (`"type": "module"`), dependency-free, needs Node 19+ for WebCrypto. API: `client.register({ challenge, user, … domain, attestation, customProperties })`, `client.authenticate({ challenge, … })`, `server.verifyRegistration(registration, expected)`, `server.verifyAuthentication(authentication, expected, …)`, where `expected` is `{ challenge, origin, userVerified?, counter?, domain?, verbose? }` (https://github.com/passwordless-id/webauthn/blob/main/docs/registration.md, fetched 2026-11-06). The `counter` check is optional "since some authenticators (like Apple) do not increment it". **Attestation is not verified** ("delivered as-is, purely informational"). It returns an authenticator name and icon from its AAGUID list, which is handy for naming. The client and server are a pair with their own JSON shape, so it isn't interchangeable with the standard `toJSON()` shape. Smaller and simpler than SimpleWebAuthn, but with about 1% of the usage.

### 2.4 Oslo (`@oslojs/webauthn`) and Lucia

- `@oslojs/webauthn` 1.0.0 (2024-09-19) offers low-level parsing (`parseAttestationObject`, authenticator-data flags, `verifyRelyingPartyIdHash`, COSE key helpers). You write the ceremony yourself, and it "does not support attestation extensions and also does not provide APIs for verifying attestation statements" (README, https://github.com/oslo-project/webauthn, fetched 2026-11-06).
- **Deprecated on 2026-07-29.** Pilcrow's post "https://pilcrowonpaper.com/blog/18" (2026-07-29) deprecates Arctic and "most" Oslo npm packages. `@oslojs/encoding` stays because Astro uses it, until roughly 2028. npm shows `@oslojs/webauthn`, `@oslojs/crypto` and `arctic` as deprecated ("Package no longer supported") as of 2026-11-06. Repos are not archived but idle (webauthn last pushed 2024-09-22).
- **Lucia** was deprecated in March 2025 (npm message: "see https://lucia-auth.com/lucia-v3/migrate"). The site (updated July 2026, https://lucia-auth.com/) is now a learning resource with a single-file session example and a link to the "Auth Book". The 2026-07-29 post says its examples are archived and the author is moving on. **Don't build on Oslo or Lucia.**

### 2.5 `@github/webauthn-json`

Deprecated; repo archived (last push 2025-08-25). README: "As of March 2025, stable versions of all major browsers now support … `parseCreationOptionsFromJSON` … `parseRequestOptionsFromJSON` … `.toJSON()`. These should be used instead." Useful only as proof that a hand-rolled browser side can be about 10 lines today. SimpleWebAuthn's browser package still adds error mapping, autofill (conditional UI) wiring, abort handling and Signal API wrappers.

### 2.6 `@hexagon/webauthn`, `webauthn-p256`, `ox`

- `@hexagon/webauthn`: dead (last modified 2022-05-20, deprecated, 21 downloads a week). Hexagon's `@hexagon/base64` lives on as a SimpleWebAuthn dependency.
- `webauthn-p256` (wevm): P-256 signing and verification helpers for smart-wallet passkeys (`@noble/curves`); repo archived 2024-11-07. Its successor is the WebAuthn and P-256 modules in `ox` 1.8.13, a large Ethereum toolkit (zod, abitype, scure, noble). For comparison only: neither is a relying-party library (no challenge, origin, RP ID or attestation ceremony), so neither suits admin login.

### 2.7 Better Auth passkey plugin

Docs: https://www.better-auth.com/docs/plugins/passkey (fetched 2026-11-06). Package `@better-auth/passkey` 1.7.18 (2026-11-05), MIT, depends on **`@simplewebauthn/server ^13.3.2` and `@simplewebauthn/browser ^13.3.0`** (not yet v14).

- Options: `rpID` (domain or a registrable parent, not a public suffix; `localhost` for dev), `rpName`, `origin` (**string or array**, no trailing slash; defaults to the `baseURL` origin plus matching `trustedOrigins`), `authenticatorSelection` (`residentKey` and `userVerification` both default `preferred`), `advanced.webAuthnChallengeCookie` (default `better-auth-passkey`: the challenge travels in a signed cookie, which suits serverless), and `registration.{ requireSession (default true), resolveUser, afterVerification, extensions }`.
- Schema, `passkey` table (https://raw.githubusercontent.com/better-auth/better-auth/main/packages/passkey/src/schema.ts, fetched 2026-11-06): `name?` string, `publicKey` string, `userId` string (FK, indexed), `credentialID` string (indexed), `counter` number, `deviceType` string, `backedUp` boolean, `transports?` string, `createdAt?` date, `aaguid?` string. **No `lastUsedAt`.**
- Client: `passkey.addPasskey({ name, authenticatorAttachment, … })`, `signIn.passkey({ autoFill })` (conditional UI with `autocomplete="username webauthn"`), `passkey.listUserPasskeys`, `passkey.deletePasskey`, `passkey.updatePasskey` (rename).
- A good model for a Payload plugin's schema and endpoints. Can't be reused directly, since it's bound to Better Auth's session and adapter layer.

### 2.8 Auth.js / NextAuth passkey provider

Docs: https://authjs.dev/getting-started/authentication/webauthn (fetched 2026-11-06, no page date). **"Experimental and not recommended for production use."** Needs `experimental: { enableWebAuthn: true }`, `next-auth@5.0.0-beta.8`+ (v5 is still beta; `next-auth` latest on npm is 4.24.15), Node ≥ 20, and a database adapter with an `Authenticator` model: `credentialID`, `userId`, `providerAccountId`, `credentialPublicKey`, `counter`, `credentialDeviceType`, `credentialBackedUp`, `transports?`. Only the Prisma adapter is documented. `@auth/core` 0.41.3's peer deps still pin **SimpleWebAuthn ^9**, three majors behind. Not a fit.

### 2.9 Recommendation

**Use `@simplewebauthn/server` + `@simplewebauthn/browser` v14 (`^14.0.3` / `^14.0.0`).** If the plugin must support Node 20 hosts, pin `^13.3.3` and plan the move.

1. **Maintenance and security response.** It is the only actively maintained, full-ceremony TypeScript RP library: two security releases and three feature releases in Sept 2026, commits in late October 2026, and build provenance. Oslo, Lucia, webauthn-json and webauthn-p256 are deprecated or archived.
2. **Ecosystem gravity.** About 9.7 M downloads a week. Better Auth (3 M a week) and Auth.js both build on it, and Craft CMS's own admin uses `@simplewebauthn/browser` (section 6.5). Bugs surface and get fixed quickly.
3. **Ergonomics.** Array `expectedOrigin`/`expectedRPID` (local, preview and production), function `expectedChallenge` (single-use, server-held challenges), a typed `WebAuthnCredential` that maps straight onto a Payload collection, `credentialDeviceType`/`credentialBackedUp`/`aaguid` for the management UI, and `sendSignal()` for keeping password managers in sync after deletes and renames.
4. **Size.** The browser side is about 8.5 kB gzipped with no dependencies. The server's `@peculiar/*` tree only loads in Node, so it never reaches the admin bundle. Import it only from server files (endpoints and hooks), never from `payload.config.ts` client paths.
5. **Node-only is fine.** It uses WebCrypto, so the same code works on Vercel's Node runtime with no `node:crypto` shims.

Fallback: `@passwordless-id/webauthn` if dependency count matters more than attestation and ecosystem; it is maintained but small. Avoid building on Better Auth or Auth.js, since both bring a whole auth framework that conflicts with Payload's own.

---

## 3. App-level PIN/passcode security

### 3.1 NIST SP 800-63B Rev 4: status

- **Final.** SP 800-63B-4 is final. The CSRC history lists "07/31/25: SP 800-63B-4 (Final)" and gives the publication date as July 2025. It supersedes SP 800-63B (2020). Sources: https://csrc.nist.gov/pubs/sp/800/63/b/4/final (fetched 2026-11-06) and the HTML edition at https://pages.nist.gov/800-63-4/sp800-63b.html (fetched 2026-11-06). Some secondary sources give 1 August 2025 as the publication or withdrawal date; the CSRC history says 31 July 2025.
- **The syncable authenticators supplement is folded in.** SP 800-63Bsup1, "Incorporating Syncable Authenticators", was published in April 2024. Secondary reporting says it was withdrawn on 1 August 2025 and "superseded in its entirety by SP 800-63B-4". Rev 4 now carries a normative Appendix B on syncable authenticators. The CSRC sup1 page now returns 404 (fetched 2026-11-06), so I could not read the withdrawal notice itself; the claim comes from search summaries such as https://nat.sakimura.org/2024/04/23/supplement-to-nist-sp800-63b-was-published-it-adds-passkey-to-aal2/. **Uncertain on the exact withdrawal wording.**

All quotes below are from https://pages.nist.gov/800-63-4/sp800-63b.html (fetched 2026-11-06).

### 3.2 NIST Rev 4: passwords (Sec. 3.1.1)

- **Length.** "Verifiers and CSPs SHALL require passwords that are used as a single-factor authentication mechanism to be a minimum of 15 characters in length. Verifiers and CSPs MAY allow passwords that are only used as part of multi-factor authentication processes to be shorter but SHALL require them to be a minimum of eight characters in length." Verifiers SHOULD permit a maximum of at least 64 characters.
- **Composition and rotation.** "Verifiers and CSPs SHALL NOT impose other composition rules (e.g., requiring mixtures of different character types)". They also "SHALL NOT require subscribers to change passwords periodically", but SHALL force a change on evidence of compromise.
- **Blocklist.** Verifiers SHALL compare the whole prospective password against "a blocklist that contains known commonly used, expected, or compromised passwords". They SHALL give the reason for a rejection. The list need not be huge, because "the blocklist is used to defend against online attacks, which are already limited by the throttling requirements".
- **Password managers.** "Verifiers SHALL allow the use of password managers and autofill functionality", and SHOULD permit paste.
- **Storage.** "Passwords SHALL be salted and hashed using a suitable password hashing scheme. Password hashing schemes take a password, a salt, and a cost factor as inputs…"
  - The salt "SHALL be at least 32 bits".
  - "The chosen cost factor SHOULD be as high as practical without negatively impacting verifier performance. It SHOULD be increased over time".
  - An approved scheme from the latest SP 800-132 (PBKDF2) "or updated NIST guidelines on password hashing schemes SHOULD be used".
  - A reference to the scheme and cost factor SHOULD be stored with each password, so hashes can be migrated later.
  - Note: the phrase "one-way key derivation function" is from Rev 3. Rev 4 says "password hashing scheme".
- **Pepper (keyed hash).** "verifiers SHOULD perform an additional iteration of a keyed hashing or encryption operation using a secret key known only to the verifier… The secret key value SHALL be stored separately from the hashed passwords. It SHOULD be stored and used within a hardware-protected area, such as a hardware security module or trusted execution environment". With it, "brute-force attacks on the hashed passwords are impractical as long as the secret key value remains secret". This is a SHOULD.
- **Rate limiting (Sec. 3.2.2).** "Unless otherwise specified in the description of a given authenticator, the verifier SHALL limit consecutive failed authentication attempts using a specific authenticator on a single subscriber account to no more than 100 by disabling that authenticator." When more than one authenticator is involved in an excessive number of attempts, both SHALL be disabled. A disabled authenticator must be re-bound to the account (Sec. 4.1) before it can be used again. The 100 is an upper bound; agencies may set lower limits.

### 3.3 NIST Rev 4: activation secrets (Sec. 3.2.10)

An activation secret is the PIN or passphrase that unlocks a multi-factor authenticator, such as a passkey's local PIN.

- **Length.** "Authenticators that use activation secrets SHALL require the secrets to be at least four characters in length and SHOULD require the secrets to be at least six characters in length."
- **Numeric allowed.** "Activation secrets MAY be entirely numeric (i.e., a PIN)."
- **Blocklist.** One SHOULD be used to discourage common values, for example "123456".
- **Retry limit: 10, not 100.** "The authenticator or verifier SHALL implement a retry-limiting mechanism that limits the number of consecutive failed activation attempts using the authenticator to no more than 10… Once the limit of attempts is reached, the authenticator SHALL be disabled, and a different authenticator SHALL be required for authentication."
- **Where the secret lives.** "the activation secret SHALL remain within the authenticator and its associated user endpoint". At AAL3, verification must happen in hardware (secure element, TPM or TEE). "At AAL2, if a hardware-protected environment is not used, the authenticator SHALL use the activation secret to derive a key used to decrypt the authentication key."
- **Separate from the device unlock.** "Submitting the activation factor SHALL be a separate operation from unlocking the host device (e.g., smartphone). However, the same activation factor used to unlock the host device MAY be used".

**What this means for the plugin.** In NIST's model a PIN is an *activation secret* that stays on the device and unlocks a key there. A short PIN that the server verifies is not an activation secret. Under Sec. 3.1.1 it would be a *password*, which must be at least 8 characters even as part of MFA. The NIST-aligned way to offer "PIN unlock" is therefore one of two things:

- a WebAuthn credential with `userVerification: 'required'`, so the platform checks the PIN or biometric locally; or
- a device-held key, as in 3.7.

A server-checked 4–6 digit PIN is acceptable only as a convenience re-unlock of a session that is already authenticated (see 3.5 and 4.4). It should not be called a factor.

### 3.4 NIST Rev 4: look-up secrets, recovery codes, biometrics and syncable authenticators

**Look-up secrets (Sec. 3.1.2)**
- "Look-up secrets SHALL be at least six decimal digits (or equivalent) in length".
- Secrets shorter than 112 bits (the SP 800-131A strength) "SHALL be stored in a salted and hashed form using a suitable password hashing scheme", with a salt of at least 32 bits.
- Their use is rate-limited under Sec. 3.2.2 (the 100-attempt cap).
- The Rev 3 "20 bits of entropy" rule is **not** in Rev 4. Rev 4 sets the floor at six decimal digits instead, which is about 20 bits.

**Saved recovery codes (Sec. 4.2)**
- They "SHALL be stored in the subscriber account in hashed form using an approved one-way function".
- They are throttled under Sec. 3.2.2.
- Each is single use: after one is used, the CSP "SHALL invalidate that recovery code and SHALL issue a new saved recovery code".

**Biometrics (Sec. 3.2.3)**
- "Biometrics SHALL only be used as part of multi-factor authentication with a physical authenticator (i.e., 'something you have')."
- "An alternative non-biometric authentication option SHALL always be provided".
- FMR of "one in 10000 or better for all demographic groups"; FNMR SHOULD be under 5%.
- PAD SHOULD be used for fingerprint and iris and SHALL be used for face. Voice SHALL NOT be used.
- Attempt limits: at most 5 consecutive failures, or 10 with PAD. After that, a delay of at least 30 s before each further attempt, up to an overall limit of 50 (100 with PAD). Then biometric authentication is disabled.
- Practical consequence: a web app never sees a biometric. It only sees a WebAuthn assertion with the UV flag set.

**Syncable authenticators, i.e. passkeys (Sec. 2.3, 3.2.13, Appendix B)**
- "Since syncable authenticators… require the private key to be exportable, syncable authenticators SHALL NOT be used at AAL3."
- They can reach **AAL2**, subject to Appendix B:
  - keys in the sync fabric are encrypted with keys of at least 112-bit strength;
  - private-key operations happen on the local device;
  - access to the sync fabric is protected by AAL2-equivalent MFA.
- **AAL3** needs non-exportable, hardware-bound keys (security keys, device-bound passkeys) that are FIPS 140 Level 1+ validated.
- WebAuthn flags (Appendix B, WebAuthn Level 3):
  - UP: verifiers "SHOULD confirm" it.
  - UV: verifiers "SHALL indicate that UV is preferred and SHALL inspect responses… If the user is not verified, agencies SHALL treat the authenticator as a single-factor cryptographic authenticator."
  - BE and BS: MAY be used to set policy. Verifiers "SHOULD NOT condition acceptance based on [Backup State] for public-facing applications".
- Related status: **WebAuthn Level 3 became a W3C Recommendation on 25 August 2026** (https://www.w3.org/TR/webauthn-3/, fetched 2026-11-06).

**Reauthentication and timeouts (Sec. 2.2.3, 2.3.3, 5.2)**
- **AAL2:** the overall timeout "SHOULD be no more than 24 hours" and the inactivity timeout "SHOULD be no more than 1 hour". Crucially for a lock screen: "When the inactivity timeout has occurred but the overall timeout has not yet occurred, the verifier MAY allow the subscriber to reauthenticate using only a successful password or biometric comparison in conjunction with the session secret".
- **AAL3:** the overall timeout "SHALL be no more than 12 hours", and the inactivity timeout "SHOULD be no more than 15 minutes". Reauthentication is the same as initial authentication.
- "Session activity SHALL reset the inactivity timeout, and successful reauthentication during a session SHALL reset both timeouts."
- Usability guidance: prompt the user shortly before an inactivity timeout, "e.g., two minutes before".

### 3.5 Why a 4–8 digit PIN needs more than hashing

The keyspace is tiny: 10^4 to 10^8 values. Hashing alone cannot protect it.

- **Offline.** A 4-digit PIN behind 600k-iteration PBKDF2 falls to an offline attacker in seconds on one GPU. An 8-digit PIN takes hours to days. Argon2id or scrypt with OWASP parameters (about 50–100 ms each) gives roughly 10^4 × 0.1 s ≈ 17 minutes for every 4-digit PIN on one core. Brute force is trivially parallel.
- **Online.** Without a limit, an attacker can simply try all 10,000 values.

So security has to come from the following. The hash only adds a modest cost on top.

1. **Server-side attempt limits, stored in the database and updated atomically.** Increment with `$inc` (Mongo) or `UPDATE … SET n = n + 1 RETURNING n` (SQL), and decide from the returned value, so parallel guesses can't race past the limit.
   - Payload's own `incrementLoginAttempts` does exactly this with `payload.db.updateOne({ data: { loginAttempts: { $inc: 1 } } })`. It then re-checks the returned count and, on a parallel-attempt race, revokes sessions created in a 20 s window. Source: `node_modules/payload/dist/auth/strategies/local/incrementLoginAttempts.js`, Payload 3.90.2, read 2026-11-06.
   - NIST's ceiling for activation-style secrets is 10. A plugin should default to about 5, matching Bitwarden's PIN.
   - On reaching the limit: **drop the PIN and require full login** (passkey or password), rather than a timed lockout an attacker can wait out.
   - Never reset the counter when the PIN is changed.
2. **Bind the PIN to a device secret.** Make the PIN meaningful only together with a key the device holds. For example, the server stores `HMAC(serverPepper, deviceKeyId ‖ PIN)`, and the request must also carry a signature from a non-extractable device key (3.7). Then a database leak, or a PIN observed over someone's shoulder, is useless without the device.
3. **Unlock only an existing session.** The PIN should never be a login factor. It re-opens a session that is still within its overall lifetime and was started with a full login. This matches NIST AAL2's "password or biometric comparison in conjunction with the session secret". If the session cookie is gone, the PIN is worthless.
4. **Pepper with a server secret.** Use HMAC-SHA256 with a key outside the database (an environment variable, or ideally a KMS). Then a database dump alone allows no offline guessing, which is NIST's "keyed hashing… stored separately" SHOULD.
   - Order: `hash = KDF(salt, HMAC(pepper, pin))`. Alternatively, HMAC the KDF output, OWASP's "post-hashing" approach with "the pepper… acting as the HMAC key" (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html, fetched 2026-11-06).
   - OWASP notes a pepper "should be stored separately from the password database" and on its own "provides no additional secure characteristics". Treat it as defence in depth.
   - Pepper rotation: Payload added a versioned `PAYLOAD_SECRET` keyring (PR #17674, merged 2026-08-11). A plugin could derive its pepper from that, or keep its own versioned key.
5. **Constant-time comparison:** `crypto.timingSafeEqual`, after checking lengths, because it throws on unequal lengths. Payload itself moved from `scmp` to `timingSafeEqual` (PR #15322, merged 2026-01-26).
6. **Blocklist trivial PINs** (`0000`, `1234`, repeats, sequences, birth years), as NIST Sec. 3.2.10 SHOULD. Make 6 digits the default, which NIST SHOULDs, and allow 4 as the floor.

### 3.6 Hashing PINs and passwords in Node without native builds

**OWASP Password Storage Cheat Sheet** (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html, fetched 2026-11-06; no page date shown)

| Algorithm | OWASP parameters (verbatim) |
|---|---|
| Argon2id | m=47104 (46 MiB), t=1, p=1 · **m=19456 (19 MiB), t=2, p=1** · m=12288 (12 MiB), t=3, p=1 · m=9216 (9 MiB), t=4, p=1 · m=7168 (7 MiB), t=5, p=1 |
| scrypt | **N=2^17 (128 MiB), r=8, p=1** · N=2^16 (64 MiB), r=8, p=2 · N=2^15 (32 MiB), r=8, p=3 · N=2^14 (16 MiB), r=8, p=5 · N=2^13 (8 MiB), r=8, p=10 |
| bcrypt | work factor of at least 10; 72-byte input limit |
| PBKDF2 | HMAC-SHA256 **600,000**; HMAC-SHA512 220,000; HMAC-SHA1 1,400,000 (legacy only) |

**Options**

- **`crypto.scrypt` (Node built-in, no dependency).** Defaults are `cost` N=16384, `blockSize` 8 and `parallelization` 1. `maxmem` defaults to 32 MiB, and "It is an error when (approximately) `128 * N * r > maxmem`" (https://raw.githubusercontent.com/nodejs/node/main/doc/api/crypto.md, fetched 2026-11-06).
  - OWASP's N=2^17, r=8 needs about 128 MiB, so pass `maxmem: 256 * 1024 * 1024`.
  - Alternatively, use the N=2^15, r=8, p=3 row (32 MiB): it fits the default and is lighter on a serverless function's memory.
  - This is the safest choice for a plugin: zero dependencies, it runs anywhere Payload runs, and the async version uses the libuv threadpool.
- **`crypto.argon2` / `argon2Sync` (Node built-in).** Added in **Node v24.7.0**. It takes `message`, `nonce` (at least 8 bytes), `parallelism`, `tagLength`, `memory` (in KiB) and `passes`, plus an optional `secret`, which is a native pepper input. Same source.
  - Vercel offers Node 26.x (default), 24.x and 22.x (https://vercel.com/docs/functions/runtimes/node-js/node-js-versions, last updated 2026-02-27).
  - **Payload 3.91.0 sets the minimum to Node 20.18.1** (release notes, 2026-10-15), so a plugin can only use `crypto.argon2` with feature detection and a scrypt fallback.
  - **Uncertain:** whether the docs mark it experimental; I found no separate stability marker in its section.
- **`@node-rs/argon2`.** Rust bindings through napi-rs. Prebuilt binaries ship as per-platform `optionalDependencies` (linux-x64-gnu/musl, linux-arm64, darwin, win32, freebsd and android), with no node-gyp and no postinstall step. Latest is 2.2.2, modified 2026-10-06 (`npm view`, 2026-11-06).
  - It works on Vercel because Vercel installs on linux-x64.
  - **Next.js 16.3.8 already lists `@node-rs/argon2`, `@node-rs/bcrypt`, `argon2` and `bcrypt` in its built-in `serverExternalPackages` list** (`node_modules/next/dist/lib/server-external-packages.jsonc`, read 2026-11-06), so they are not bundled.
  - Risk for a plugin: platform-specific optional dependencies can be skipped by some lockfile or CI setups (pnpm `supportedArchitectures`, Docker image builds on macOS). It also won't run on edge or Workers runtimes.
- **`argon2` (node-argon2).** C bindings that ship prebuilds but fall back to node-gyp. More fragile on unusual platforms, and pnpm 11 requires an `allowBuilds` approval for its install script. Not recommended for a plugin dependency.
- **`hash-wasm`.** WASM compiled from C, with zero dependencies. It covers argon2id, scrypt, bcrypt and PBKDF2, and runs in Node, browsers and edge runtimes. Latest is **4.12.0, last modified 2024-11-19**, so it is stale but stable (https://github.com/Daninet/hash-wasm; `npm view`, 2026-11-06). WASM memory is allocated per call, so 19–46 MiB is fine.
- **`@noble/hashes`.** Pure JS: pbkdf2, scrypt, argon2d/i/id. Version 2.4.0, modified 2026-08-27; v2 is ESM-only and needs Node 20.19+ (https://github.com/paulmillr/noble-hashes, fetched 2026-11-06).
  - Its README warns that "Argon2 can't be fast in JS, because there is no fast Uint64Array", and that being "5x slower than native code means brute-forcing attackers have bigger advantage". It suggests scrypt instead.
  - It was audited by Cure53 at v1.0.0 (January 2022), except argon2, blake3 and some others, which "have not been audited".
  - Not recommended for server use when `node:crypto` is available.

**What Payload itself does** (verified from source)

- Installed **Payload 3.90.2** (`node_modules/payload/dist/auth/strategies/local/generatePasswordSaltHash.js`, read 2026-11-06):
  - new hashes use **PBKDF2-HMAC-SHA256 with 600,000 iterations, a 32-byte key and a 32-byte random salt**, stored with the prefix `pbkdf2-sha256-v1:`;
  - hashes with no prefix are treated as **legacy: 25,000 iterations and a 512-byte key**, still verified.
  - The brief's "25000 iterations, SHA-256, 512 bytes" is therefore the *legacy* format.
- Upstream `main` and **v3.93.0 (2026-11-04)** add `auth.passwordHashIterations` (100000 | 600000, prefixes `pbkdf2-sha256-100k-v1:` / `pbkdf2-sha256-v1:`) for runtimes such as Cloudflare Workers that reject high PBKDF2 counts (PR #19074, merged 2026-10-29; https://github.com/payloadcms/payload/blob/main/packages/payload/src/auth/strategies/local/generatePasswordSaltHash.ts, fetched 2026-11-06).
- `isCurrentPasswordHash` lets Payload tell old hashes from current ones.
- **Uncertain:** the exact release that moved Payload from 25k to 600k. It is before 3.90.2; I did not pin it.

**Recommendation.** Use built-in `crypto.scrypt` (N=2^15, r=8, p=3, or N=2^17 with raised `maxmem`), with an HMAC pepper and a versioned prefix. Use `crypto.argon2` when the runtime is Node 24.7+. Add `hash-wasm` only if an edge runtime must be supported. For a PIN, a lighter cost (about 50 ms) is defensible, because the attempt limit and pepper carry the security (3.5) and a heavy KDF only adds latency and denial-of-service surface.

### 3.7 "Trusted device + PIN" with WebCrypto, versus a WebAuthn credential

**WebCrypto device key**
- Call `crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])`.
- With `extractable: false`, `exportKey()` and `wrapKey()` fail for the private key; "the public key is always extractable" (https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey, fetched 2026-11-06).
- The Web Crypto spec marks `CryptoKey` as `[Serializable]`, and serialisation preserves `[[extractable]]` (https://w3c.github.io/webcrypto/, fetched 2026-11-06). So the key object can be `put()` into IndexedDB and used after reloads without its bytes ever reaching script.
- The spec expects "most authors will make use of the Indexed Database API". It warns users may clear an origin's storage, "potentially destroying keys", so keys are lost with site data. They are origin-scoped and need a secure context.
- **Flow:**
  1. Register: the server stores the public key (JWK/SPKI) against the user and session.
  2. Unlock: the server issues a nonce, the browser signs `nonce ‖ sessionId`, and sends it with the PIN.
  3. The server verifies the signature, checks the HMAC'd PIN and decrements the attempts left.
- **Limits:**
  - The key is software-protected. Browsers may keep it in the profile, not a TPM.
  - Any XSS on the origin can *use* the key while the page is open, though it can't export it.
  - The PIN check happens on the server, so NIST would see this as "password + something you have", not a hardware-verified activation secret.
  - This is what Device Bound Session Credentials (DBSC) aim to standardise for sessions. NIST Rev 4 Sec. 5.1 cites DBSC as a way to make session secrets proof-of-possession.

**WebAuthn with `userVerification: 'required'` (recommended)**
- A platform authenticator gives the same "device + PIN or biometric" property, with the PIN checked locally in hardware (Secure Enclave, TPM or StrongBox). The secret never reaches the server, and phishing resistance is built in.
- Per WebAuthn L3, user verification may be "a touch plus pin code, password entry, or biometric recognition", and "an authenticator that supports user verification is multi-factor capable" (https://www.w3.org/TR/webauthn-3/, Recommendation of 25 August 2026, fetched 2026-11-06).
- The server must check the **UV flag** in authenticator data. NIST Appendix B says without UV it is single-factor.
- This is the industry-standard route, and it makes a home-grown PIN optional.
- Offer a plugin-managed PIN only as a fallback for devices without a platform authenticator, for example a shared desktop without Windows Hello.

**PRF extension (for client-side encryption, if needed)**
- `prf` asks the credential for a deterministic 32-byte secret for a given salt (`eval` at create, `evalByCredential` at get), which can become an AES key (https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions, fetched 2026-11-06).
- The spec maps it onto CTAP2 `hmac-secret`'s *UV* PRF ("that PRF MUST be the one used for when user verification is performed. This overrides the UserVerificationRequirement if necessary").
- Support snapshot (Corbado, data from August 2026, article last modified 2026-09-29, https://www.corbado.com/blog/passkeys-prf-webauthn):
  - **Android Chrome/Edge:** yes, through Google Password Manager.
  - **macOS 15+ / iOS 18+:** iCloud Keychain in Safari 18+, Chrome 132+ and Firefox 139+. iOS 18.4+ is recommended because earlier 18.x had hybrid bugs. Security-key PRF in Safari needs 26.4+, with open WebKit bugs.
  - **Windows Hello:** only after the February 2026 Windows 11 update, with Chrome/Edge 147+ or Firefox 148+.
  - **Firefox Android 149+:** shipped March 2026.
  - **Third-party password managers:** vary.
  - Corbado's advice: treat PRF "as an enhancement, not a hard dependency". This is a third-party source, flagged as such.
- The plugin probably does not need PRF unless it encrypts something on the client.

**Platform fallback behaviour (the "passcode" story)**
- Platform authenticators already fall back to the device passcode or password:
  - Face ID needs the passcode after restart, after 48 hours without unlock, after "five unsuccessful attempts to match a face", and in other cases (https://support.apple.com/en-us/102381, published 2026-09-18).
  - On a Mac, Touch ID doesn't replace the login password, "which is still required after device startup, restart, or logout" (https://support.apple.com/guide/security/sec067eb0c9e/web, published 2024-12-19).
  - Windows Hello falls back to its PIN.
- So "unlock with a passkey" already includes a passcode path. The admin's copy can say "Unlock with Touch ID, Face ID, Windows Hello or your device passcode" without the plugin storing any PIN.

---

## 4. Session/lock-screen patterns

### 4.1 GitHub sudo mode

Source: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/sudo-mode (fetched 2026-11-06).

- GitHub prompts for authentication "before you perform a protected high-impact action". Examples:
  - deleting the account, changing email, adding SSH keys, authorising OAuth apps;
  - creating PATs, generating or removing client secrets;
  - webhooks, organisation membership and security, enterprise settings, rulesets, recovery codes.
- **Duration:** "GitHub has a two-hour session timeout period before prompting you for authentication again", and "any sensitive action that you perform will reset the timer". Ordinary browsing does not reset it.
- **Factors:** password, passkey, security key, GitHub Mobile (number matching), TOTP, and an email code for social-login accounts. "Text messages are not supported for use on the sudo prompt"; SMS-only users get the password prompt instead.
- It is enforced server-side per protected endpoint. The prompt is just the UI for satisfying a server check.

### 4.2 Google, and a UK banking app

- **Google "Verify it's you":** "To help protect your account and data, you must verify it's you when you complete sensitive actions." Examples are changing sign-in credentials, viewing saved passwords and exporting data. You verify with a registered device, security key or 2SV code. If Google can't verify you, it "may block sensitive actions for up to 7 days" while normal use continues (https://support.google.com/accounts/answer/7162782, fetched 2026-11-06).
  - The pattern: step-up is separate from staying signed in, and failure degrades to read-only use rather than a lockout.
- **Monzo:**
  - "By default we ask you for your Monzo PIN" to authorise payments, and "you can also authorise payments and other sensitive actions with your fingerprint or face".
  - There's "no need to provide authentication each time you open the app because all payments are protected using your PIN or biometrics".
  - Optional App Lock asks "every time it is launched" and is described as a privacy feature.
  - Source: https://monzo.com/faq/learn-more/biometric-authentication, fetched 2026-11-06, undated. Search summaries of Monzo help say it otherwise re-authenticates on open every 90 days (**unverified**).
  - The pattern separates a *privacy lock* (opening or viewing) from *step-up* (doing something sensitive). The plugin should keep the same distinction: an idle lock screen protects what's on screen, and step-up protects destructive or security actions.

### 4.3 Idle re-lock in password managers: lock is client-side

- **Bitwarden** (https://bitwarden.com/help/vault-timeout/, fetched 2026-11-06, undated):
  - "Locking your vault will maintain vault data on the device, so unlocking your vault can be done offline." "Logging out of your vault completely removes all vault data from your device."
  - Unlock takes the master password, PIN or biometrics, and needs no 2FA.
  - Web vault timeouts: a time period, on browser refresh, or custom. "Refreshing the browser locks the vault"; closing the tab logs out.
  - Inactivity is measured from the last interaction with Bitwarden.
- **Bitwarden PIN** (https://bitwarden.com/help/unlock-with-pin/, fetched 2026-11-06):
  - "you will be automatically logged out after five failed attempts at entering the PIN". Logging out wipes the PIN.
  - PIN unlock is offered for mobile, browser extension and desktop. The page **does not list the web vault**.
  - It warns that a PIN "can weaken the level of encryption that protects your application's local vault database".
  - With "require master password on restart" off, the app "may not fully purge sensitive data from application memory when entering a locked state".
  - The help pages don't document the internals. A community answer says the user key is encrypted under a PIN-derived key using the account's KDF settings (https://community.bitwarden.com/t/what-key-derivation-function-is-used-for-the-pin-unlock-key/65781). **Unverified; the Security Whitepaper is the authority.**
- **1Password** (https://support.1password.com/unlock-auto-lock/, published 2026-10-29):
  - It locks on device lock or sleep, or after idle minutes. On 1Password.com, Auto-Lock is set in minutes per browser.
  - Unlock is with Touch ID, Apple Watch, Windows Hello (optionally through the TPM), Face ID or the device passcode on iOS, or Android biometrics. A "Require account password" interval forces the full password periodically.
- **Lesson.** In these products, "lock" means the *decryption key* is purged from client memory, and unlocking re-derives or unwraps it locally. That works because the secret being protected is on the client. A Payload admin has nothing on the client to protect: the session cookie gives full API access. **A client-side overlay alone is theatre.** Anyone can call `/api/...` with the cookie, open devtools, or load another admin URL.

**A server-enforced lock for Payload**
- Store per-session lock state, keyed by Payload's session id (`sid`):
  - `lastActivityAt` and `lockedAt` (or a derived "locked if now − lastActivityAt > idle");
  - `unlockedUntil`, `authTime` (last full or step-up authentication), `amr` (`['pwd']`, `['webauthn','uv']`, `['pin']`);
  - `pinAttemptsLeft`.
- Every protected request checks it server-side.
- Payload facts (Payload 3.90.2 source read 2026-11-06; https://payloadcms.com/docs/authentication/overview fetched 2026-11-06):
  - `auth.useSessions` **defaults to `true`** (`collections/config/defaults.js`). The docs: "Stateless JWTs cannot be revoked, so they stay valid until `tokenExpiration`."
  - Sessions are **stored on the user document**: a hidden `sessions` array field of `{ id, createdAt, expiresAt }`, read-only to the owner (`auth/baseFields/sessions.js`). Each login adds an entry (`auth/sessions.js addSessionToUser`). The JWT carries `sid`, and the JWT strategy rejects a token whose `sid` is no longer in `user.sessions`, then sets `req.user._sid` (`auth/strategies/jwt.js`).
  - Refresh pushes `expiresAt` forward by `tokenExpiration` (`auth/operations/refresh.js`), so this is a **sliding session**. Defaults: `tokenExpiration` 7200 s, `maxLoginAttempts` 5, `lockTime` 600000 ms.
  - As far as the 3.90.2 code shows, `createdAt` is not used to enforce an **absolute timeout**. A plugin should add one. **Uncertain:** whether 3.91+ added it.
  - Sessions came in v3.44.0 with PR #12483. Logout revokes only the current session unless `allSessions: true` is passed (search summary of release notes, **not re-verified** against 3.44.0 notes).
  - **Payload 3.91.0 (2026-10-15) backported "activity-aware auth sessions"** (PR #17854, from #17481, merged 2026-08-03 for v4). The admin now refreshes the token from mouse, keyboard, focus and route activity in a tracking window. In the final reminder window "background activity no longer refreshes the token and the user must explicitly choose to remain signed in". It coordinates across tabs through `BroadcastChannel`. It is breaking for `useAuth().tokenExpirationMs`, which is replaced by `authSession.expiresAt`.
  - Result: Payload's own idle timeout is effectively `tokenExpiration`, and a lock-screen plugin should cooperate with `useAuth().authSession` rather than fight it.
- **Where to enforce it (design notes, from the source):**
  - Payload runs auth strategies in order: each collection's custom `strategies` first, then API-key strategies, then `local-jwt` **last**. **The first strategy that returns a user wins.** A thrown error is logged and skipped (`dist/index.js`, `auth/executeAuthStrategies.js`).
  - So a plugin **cannot veto** the JWT strategy by returning `{ user: null }`. Options:
    - (a) Wrap every collection's and global's `access` functions, plus the plugin's own endpoints, with a check `isUnlocked(req)` that reads lock state by `req.user._sid`. This also covers the Local API with `overrideAccess: false` and the admin's server-rendered data. It doesn't cover `overrideAccess: true` calls, which are trusted server code.
    - (b) Register a custom strategy placed before `local-jwt` that verifies the Payload JWT itself and, when the session is locked, returns the user with a `_locked` marker or a reduced-permission identity that the access wrappers recognise.
  - API-key requests (`_strategy` ending in `-api-key`) have no `sid`. The policy must decide whether API keys bypass the lock (they normally should) and whether they may do sensitive actions at all.
  - The admin UI: add `admin.components.providers` for the overlay, and use a server-side check in the admin layout or views so a locked session cannot SSR document data.
  - Next 16 `proxy.ts` (formerly middleware) could short-circuit `/admin/*` and `/api/*`, but it would need a database read or a signed lock cookie. Treat it as an optimisation, not the boundary.
- **Trade-offs:**
  - **Short JWTs plus refresh (stateless):** no per-request database read, but there is no instant lock or revoke until expiry. Payload's docs note stateless JWTs "cannot be revoked".
  - **Sliding sessions:** good UX, but without an absolute cap a session can live forever. OWASP and NIST both require an overall cap.
  - **Server-side session records** (Payload's default): revocable and lockable at once, at the cost of one read per request. Payload already does that read, since the JWT strategy loads the user with `sessions`. A plugin can keep lock state on the same user document (an extra field on the session entry, or a parallel `lockState` array keyed by `sid`), so it costs no extra query. Payload's `sessions` field has `update: () => false` access and is written with `payload.db.updateOne`, so a plugin should write through `db.updateOne` as well, or keep its own collection keyed by `sid`.

**OWASP Session Management Cheat Sheet** (https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html, fetched 2026-11-06)
- "Common idle timeouts ranges are 2-5 minutes for high-value applications and 15-30 minutes for low risk applications."
- "All sessions should implement an absolute timeout, regardless of session activity". It cites 4–8 hours for a working day.
- An optional renewal timeout regenerates the session ID periodically.
- "The session ID must be renewed or regenerated by the web application after any privilege level change". For the plugin, that means rotating the session after unlock or step-up if it changes what the session may do.
- "Session timeout management and expiration must be enforced server-side". Client timers are only a supplement.
- "Web applications should require reauthentication after high-risk events", for example changes to password or email, or account recovery.

**OWASP ASVS 5.0.0** (released 30 May 2025; https://owasp.org/www-project-application-security-verification-standard/; requirements from https://github.com/OWASP/ASVS/blob/master/5.0/en/0x16-V7-Session-Management.md, fetched 2026-11-06)
- In ASVS 4.0, session management was **V3**. In **5.0 it is V7**, and the timeouts and step-up live in V7.3 and V7.5.
- **7.1.1 (L2):** document the inactivity timeout and absolute lifetime, and justify deviations from SP 800-63B.
- **7.2.4 (L1):** "generates a new session token on user authentication, including re-authentication", and terminates the old one.
- **7.3.1 (L2):** an inactivity timeout "such that re-authentication is enforced according to risk analysis".
- **7.3.2 (L2):** "an absolute maximum session lifetime such that re-authentication is enforced".
- **7.4.1 (L1):** after logout or expiry the application "disallows any further use"; stateless tokens need extra revocation.
- **7.4.3 (L2):** offer to end all other sessions after any authentication factor changes.
- **7.5.1 (L2):** "full re-authentication before allowing modifications to sensitive account attributes", such as email, phone and MFA settings.
- **7.5.3 (L3):** "further authentication with at least one factor or secondary verification" before highly sensitive transactions.
- Implication: changing the email or password, or adding or removing a passkey or PIN, needs **full** re-authentication (a passkey with UV, or the password), not the lock-screen PIN.

### 4.4 Representing and enforcing step-up

- **Standards vocabulary.**
  - OIDC ID tokens carry `auth_time` (when the user last actively authenticated), `acr` (assurance class) and `amr` (methods, for example `pwd`, `hwk`, `user`, `pin`). A relying party can request freshness with `max_age`.
  - **RFC 9470, OAuth 2.0 Step-Up Authentication Challenge** (September 2023, https://www.rfc-editor.org/rfc/rfc9470.html, fetched 2026-11-06): a resource server answers with `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="…", max_age=…`. The client re-authenticates and returns with a token whose `acr` and `auth_time` satisfy it. If the authorisation server can't meet the request, it fails with `unmet_authentication_requirements`.
  - The plugin can copy this shape for its own API, for example a 401 or 403 with `error: 'step_up_required', maxAge: 300, methods: ['webauthn']`, which the admin UI turns into a passkey prompt and a retry.
- **Server record, not a separate cookie.** Keep `authTime`, `amr` and `stepUpUntil` on the server-side session record keyed by `sid`.
  - A separate "sudo" cookie (signed, HttpOnly, short-lived, bound to `sid`) works too, but it is a second credential to protect, rotate and clear on logout.
  - Changing Payload's JWT to carry `auth_time` would mean re-issuing tokens and wouldn't survive Payload's own refresh. The session-record approach fits Payload's existing per-request user load.
  - Step-up lifetime: GitHub uses 2 hours, reset by each sensitive action. For a CMS admin, 5–15 minutes is more typical for destructive actions.
  - Lock-screen unlock and step-up are different levels: a PIN unlock should *not* satisfy step-up.
- **Enforcing it in Payload (design sketch).**
  - Access functions run for REST, GraphQL and the Local API unless `overrideAccess: true`. Wrap `access.delete`, `access.update` on chosen collections (`users`, API-key fields, the plugin's own credentials collection), and global `update`, with `requireFresh(req, { maxAgeSec, methods })`. It reads the session record by `req.user._sid` and returns `false` (403) when the session isn't fresh. Access functions can't attach a custom error body, so for a step-up prompt the UI needs a distinct signal.
  - Better, throw a `Forbidden` or `APIError` with a status and a `data` field such as `{ stepUp: { maxAge, methods } }` from a `beforeOperation`, `beforeChange` or `beforeDelete` hook, which can inspect `operation`, `data` and `originalDoc`. That allows field-level triggers, for example when `email`, `password`, `roles` or `enableAPIKey` change.
  - Hooks also run for Local API calls. Skip the check when there is no `req.user` (trusted server code) or when `req.context.skipStepUp` is set by the plugin's own internal writes.
  - Keep the policy in one place: a `sensitiveOperations` config (collection slug plus operation plus optional field predicate) that both the access wrapper or hook and the admin UI read, so the UI can prompt *before* the user submits.
  - Rotate the session after a successful step-up if it raises privilege. OWASP and ASVS 7.2.4 want a new token on re-authentication; Payload's refresh issues a new token for the same `sid`, so a true rotation means a new session entry.

---

## 5. Existing Payload work

Research date: 2026-11-06. npm figures come from `registry.npmjs.org` and `api.npmjs.org/downloads/point/last-week/<pkg>` (week 2026-10-29 to 2026-11-04). GitHub figures come from the GitHub REST API, fetched 2026-11-06. Payload source quotes come from the `3.x` branch (`payload@3.93.0`, published 2026-11-04). Payload's `main` branch is now 4.0 beta (`4.0.0-beta.7`, 2026-11-04).

### 5.1 Landscape summary

No official Payload passkey, WebAuthn, TOTP or MFA feature exists in Payload 3.93.0 or in the 4.0 beta migration guide.

- **Issues:** GitHub issue search on `payloadcms/payload` for "passkey", "webauthn", "totp", "mfa" and "two-factor" returns nothing relevant (fetched 2026-11-06).
- **Discussions:** the long-running feature request is [Discussion #2555 "Implementing 2FA"](https://github.com/payloadcms/payload/discussions/2555) (opened 2023-04-25, 53 upvotes). It contains no Payload-team roadmap commitment. Its last comments point to community plugins (payload-totp, @assamlabs/payload-2fa).
- **Auth wishlist:** [Discussion #3298 "Improved Authentication in Payload"](https://github.com/payloadcms/payload/discussions/3298) (2023-09-08) lists "2FA via OTP … in core" as an idea. Some items on that list, such as revoking all tokens, have since shipped as `useSessions`; OTP has not.
- **Enterprise:** [payloadcms.com/enterprise](https://payloadcms.com/enterprise) (fetched 2026-11-06, page undated) advertises "SSO, SAML, OAuth … with any SAML or OAuth 2.0 identity provider" and audit logs behind "Schedule a Demo". MFA, passkeys and OIDC are not mentioned, and no licence or pricing is shown.
- **PIN or passcode:** nothing exists. npm search for "payload pin login" and "payload passcode", and GitHub search for "payload webauthn", returned no Payload package (fetched 2026-11-06). A passkey plus PIN plugin built on Payload's native sessions would therefore be a new niche.

### 5.2 Plugin inventory

Every name the brief listed was checked on npm. Names marked "not found" do not exist; don't cite them.

| npm name | Exists? | Latest (date) | Weekly dl | Payload peer | Repo (stars, last push) |
|---|---|---|---|---|---|
| `payload-auth` | yes | 3.0.0 (2026-08-05) | 14,553 | `>=3.79.1 <4`, plus `@payloadcms/ui`/`next >=3.79.1 <4`, `better-auth >=1.5 <2`, `@better-auth/passkey`, `next >=15.4.8 <17` | [payload-auth/payload-auth](https://github.com/payload-auth/payload-auth) (346★, 2026-08-05; formerly `forrestdevs/payload-better-auth`, which now redirects here) |
| `payload-auth-plugin` | yes | 0.7.13 (2026-05-18) | 5,034 | `^3.0.0` | [UPDOT/payload-auth-plugin](https://github.com/UPDOT/payload-auth-plugin) (309★, 2026-05-18; was `authsmith/payload-auth-plugin`) |
| `payload-passkey` | yes | 2.1.7 (2026-11-04) | 719 | `>=3.69.0 <4` (+ ui, translations), `next ^16` | [Robot-Inventor/payload-passkey](https://github.com/Robot-Inventor/payload-passkey) (1★, 2026-11-05; first published 2026-08-02) |
| `payload-totp` | yes | 3.0.7 (2026-10-30) | 18,348 | `^3.88.0` (+ ui, next, translations) | [GeorgeHulpoi/payload-totp](https://github.com/GeorgeHulpoi/payload-totp) (164★, 0 open issues, 2026-10-30) |
| `payload-oauth2` | yes | 1.0.21 (2026-05-12) | 26,850 | `^3` | [WilsonLe/payload-oauth2](https://github.com/WilsonLe/payload-oauth2) (198★, 8 open issues, 2026-05-12) |
| `payload-authjs` | yes | 0.10.2 (2026-05-29) | 2,227 | `^3.16.0`, `next-auth ^5.0.0-beta.25` | [CrawlerCode/payload-authjs](https://github.com/CrawlerCode/payload-authjs) (207★, 2026-05-29) |
| `@delmaredigital/payload-better-auth` | yes | 0.14.1 (2026-11-01) | 3,981 | `>=3.90.0 <4`, `better-auth >=1.7.7 <2`, `@better-auth/passkey`, `next >=16.4.1 <17` | [delmaredigital/payload-better-auth](https://github.com/delmaredigital/payload-better-auth) (74★, 0 open issues, 2026-11-02) |
| `payload-better-auth` | yes | 3.2.0 (2026-03-16) | 21 | `^3.79.0` | [benjaminpreiss/payload-better-auth](https://github.com/benjaminpreiss/payload-better-auth) (4★) |
| `@payload-auth/better-auth-plugin` | yes, **deprecated** on npm ("Package no longer supported") | 1.1.8 (2025-03-17) | 34 | none declared | superseded by `payload-auth` |
| `@payload-auth/better-auth-db-adapter` | yes, **deprecated** | 1.1.2 (2025-03-17) | – | `payload 3.28.1` (exact) | superseded by `payload-auth` |
| `@clocklimited/payload-2fa` | yes | 3.0.0-beta.1 (2025-05-27) | 529 | `^3.29.0` | [clocklimited/payload-2fa](https://github.com/clocklimited/payload-2fa) (6★, 2025-09-11): a fork of payload-totp, stale |
| `@assamlabs/payload-2fa` | yes | 1.4.1 (2026-08-25) | 147 | `^3.80.0` | no repo in npm metadata; announced in [Discussion #17955](https://github.com/payloadcms/payload/discussions/17955) (2026-08-26) |
| `@purposeinplay/payload-totp` | yes | 0.5.1 (2026-09-07) | 148 | `^3.0.0` | npm points to `purposeinplay/payload-plugins`, which returns 404 (private or removed) |
| `@plutotcool/payload-plugin-two-factor` | yes | 1.0.1 (2026-07-31) | 168 | `^3.0.0` | [plutotcool/payload-plugin-two-factor](https://github.com/plutotcool/payload-plugin-two-factor) (4★); [Discussion #17535](https://github.com/payloadcms/payload/discussions/17535) |
| `payload-passkeys`, `payload-plugin-webauthn`, `payload-plugin-passkey`, `payload-2fa`, `payload-plugin-2fa`, `@payload-bites/totp`, `@payloadcms/plugin-mfa`, `@payloadcms/plugin-sso` | **not found** on npm (fetched 2026-11-06) | – | – | – | – |

More context:

- **payload-bites:** the `@payload-bites` scope exists (audit-fields, soft-delete, activity-log and others, all updated 2026-07-15), but it has no auth package.
- **Better Auth:** its own [community adapters page](https://www.better-auth.com/docs/adapters/community-adapters) (fetched 2026-11-06) lists "payload-auth" for Payload CMS. Better Auth ships no first-party Payload adapter.
- **Auth.js:** the `payload-authjs` README carries a caution that "Auth.js is now part of Better Auth" and that Auth.js 5 may never be stable. Its passkey support arrived in [PR #45](https://github.com/CrawlerCode/payload-authjs/pull/45) (merged 2025-09-09), using Auth.js's passkey provider.

### 5.3 How each relevant plugin works

#### payload-auth (Better Auth, the most-used full replacement)

Sources: [repo docs: admin-panel.mdx and how-it-works.mdx](https://github.com/payload-auth/payload-auth/tree/main/docs/content/docs), fetched 2026-11-06. The docs site `payload-auth.dev` did not resolve (DNS ENOTFOUND) on 2026-11-06.

**Approach.** It replaces Payload auth. Three parts work together:

1. A Better Auth `DBAdapter` writes through Payload's Local API.
2. The plugin generates Payload collections from the Better Auth schema: users, sessions, accounts, verifications, `passkeys`, `twoFactors`, rate-limit, organisations and others.
3. A Payload **auth strategy** trusts Better Auth sessions.

**Admin UI.** It "rewrites `config.admin`". It replaces `/admin/login`, `/admin/signup`, `/admin/forgot-password`, `/admin/reset-password` and `/admin/two-factor-verify` with custom views. It sets `admin.routes.login` to `/login-redirect`, prepends an `RSCRedirect` to `admin.components.afterLogin`, and replaces the logout button. It also sets `admin.loginMethods` (for example `['passkey']`). The docs tell users to run `payload generate:importmap` after install.

**Credential storage.** Passkeys go in a separate `passkeys` collection managed by `@better-auth/passkey`. Sessions are Better Auth session documents, not Payload's `sessions` array.

**Weaknesses and open issues (fetched 2026-11-06):**

- [#166](https://github.com/payload-auth/payload-auth/issues/166): logout fails with MongoDB `NoSuchTransaction` (500) and leaves the session active. This matters for this repo, which uses MongoDB.
- [#154](https://github.com/payload-auth/payload-auth/issues/154): the login component logs credentials to the console.
- [#172](https://github.com/payload-auth/payload-auth/issues/172): bump Payload to 3.90.0 for GHSA-66wr-7vmr-p5jq.
- It is a heavy dependency (Better Auth plus many collections).
- The docs site was down on the day of checking.

#### @delmaredigital/payload-better-auth (Better Auth adapter, actively maintained)

Source: [README](https://github.com/delmaredigital/payload-better-auth), fetched 2026-11-06.

- **Approach:** the users collection uses `auth: { disableLocalStrategy: true, strategies: [betterAuthStrategy()] }`. The plugin registers `/api/auth/*` and injects admin UI (passkeys, 2FA, API keys, password reset, magic link and email OTP screens).
- **Payload 4:** it supports the beta early. It notes its admin screens still use the Payload 3 `--theme-*` CSS variables that Payload 4 retires.
- **Session caveat:** since 0.13, `payload.auth({ headers })` no longer extends the session unless `canSetHeaders: true` is passed and the response headers are forwarded.
- **Atomicity:** it documents that Payload's Local API has no atomic `DELETE … RETURNING` or `SET n = n + d`. Single-use token consumption is therefore read-then-write, which leaves a race window. The same limit applies to any plugin that stores one-time WebAuthn challenges in a Payload collection.
- **MongoDB:** documented on its docs site.

#### payload-passkey (Robot-Inventor: the only passkey-specific plugin)

Source: [README and source](https://github.com/Robot-Inventor/payload-passkey), fetched 2026-11-06.

- **Approach:** a wrapper around `@delmaredigital/payload-better-auth` and `@better-auth/passkey`. It *keeps Payload's default login screen* and adds a "passkey login" button through `admin.components.afterLogin` (`payload-passkey/components/PasskeyLoginButton#PasskeyLoginButton`).
- **Account screen:** passkey management is a field component on the users collection.
- **Provider:** a session-refresh provider is added through `admin.components.providers`.
- **Strategies:** it adds a Better Auth strategy *alongside* the local strategy rather than disabling it. A "payload-session-bridge" endpoint checks a trusted `Origin` and a fresh Payload session (`user._sid` and `sessions[].createdAt`) before allowing passkey registration (step-up).
- **TOTP:** it is compatible with payload-totp, but `payloadTotp()` must come after it in the plugin list.

Weaknesses:

- It is very new (first release 2026-08-02) and has 1 star.
- It pulls in all of Better Auth.
- Its setup needs `BETTER_AUTH_SECRET`, `rpID`, `origin` and `baseURL` configured separately from Payload.
- Its README tells users to run SQL migrations. MongoDB support is not stated in the README: **unverified**.
- Open issues are all Payload 4 preparation: [#220 "Payload v4 support"](https://github.com/Robot-Inventor/payload-passkey/issues/220), [#221 `definePlugin()` argument format](https://github.com/Robot-Inventor/payload-passkey/issues/221), #223 replacing Next.js router hooks with Payload UI utilities, and #224 replacing deprecated CSS tokens.

#### payload-totp (GeorgeHulpoi: the most-used native-auth extension)

Source: [README](https://github.com/GeorgeHulpoi/payload-totp) and `src/index.ts`/`src/strategy.ts` at HEAD, fetched 2026-11-06. This is the closest structural precedent for a plugin that *extends* Payload's native login instead of replacing it.

**Approach**, in four parts:

1. A custom `AuthStrategy` (`TOTP_STRATEGY_NAME`) is prepended to the collection's `auth.strategies`. It reads a second cookie, `${cookiePrefix}-totp` (a JWT signed with `payload.secret` that names `userId` and `originalStrategy`). It then delegates to the original strategy found in `payload.authStrategies` and returns the user with `_strategy: 'totp'` only if the IDs match. It guards against self-recursion.
2. It wraps every collection's and global's `access` functions with `totpAccess(...)`. Access is refused until the second factor is verified, and the README tells users to list the plugin last. In `onInit` it also wraps the collections Payload adds after plugins run (`payload-jobs`, `payload-locked-documents` writes, `payload-query-presets`, folders). It notes this pass does not survive Payload's dev-mode config reload.
3. Admin views are added at `/setup-totp` and `/verify-totp` through `admin.components.views` with `exact: true`. A provider redirects users who still owe a code. A `ui` field on the account page handles setup and removal.
4. Endpoints `POST /api/setup-totp`, `/verify-totp` and `/remove-totp` are added to root `config.endpoints`.

Supporting details:

- **Hooks:** `afterLogout` deletes the TOTP cookie, `afterRefresh` refreshes it, and `afterOperation` resets attempts on unlock.
- **Storage:** the secret is stored in a hidden `totpSecret` text field with `read/create/update: () => false`. Whether it is encrypted at rest is **unverified**; it looks like plain text in the field definition. A virtual `hasTotp` checkbox exposes enrolment state.
- **Brute force:** attempts go in a separate `totp-attempts` collection. They are kept off the user document because "Payload's login, refresh and logout write back the whole user document they read when they started, which would let someone who knows the password put the count back". The plugin reuses the collection's `maxLoginAttempts` and `lockTime`.
- **Host requirement:** the host must add a `proxy.ts` (Next 16) or `middleware.ts` (Next 15) that sets an `x-pathname` header, "Without this part, it will create an endless redirect loop". This is a recurring pain point: server components cannot read the pathname.
- **`disabled` option:** it keeps the schema (fields and collections) and registers no behaviour. This matches the official template's advice.

#### payload-auth-plugin (UPDOT, formerly Authsmith)

Source: [repo source](https://github.com/UPDOT/payload-auth-plugin), fetched 2026-11-06.

- **Approach:** separate auth for *frontend apps*. The `src/plugin.ts` header says "used for authenticating users in the frontent app". A `useAdmin` option exists. It provides OAuth2/OIDC providers, password, magic link and passkey (`@simplewebauthn/server` and `@simplewebauthn/browser`), plus an accounts collection.
- **Passkey storage:** credentials go on an *accounts* collection record (`passKey: { credentialId, publicKey, counter, transports, deviceType, backedUp }`). The challenge is held in a `__session-webpk-challenge` HttpOnly cookie for 300 s.
- **Token issue:** it issues its own JWT cookie.

Weaknesses:

- The docs link (`authsmith.com`) now redirects to a domain-for-sale page ([#155 "Documentation link broken"](https://github.com/UPDOT/payload-auth-plugin/issues/155)).
- [#160 "make issued sessions authenticate against Payload 3.90+"](https://github.com/UPDOT/payload-auth-plugin/issues/160) (2026-10-07, open) reports that after Payload 3.90 "sign-in appears to succeed and then no subsequent request is authenticated — `req.user` is null everywhere". The plugin's tokens lack the new `authVersion` protected header and sign `sid: null`. See 5.4.
- [#144](https://github.com/UPDOT/payload-auth-plugin/issues/144): it "Breaks Payload's in-built auth object".
- In the source read on 2026-11-06, passkey *registration* (`VerifyPasskeyRegistration`) takes `email` from the request body and does not require an authenticated user. Whether this allows binding a passkey to someone else's email depends on the session callback; **not verified, treat as a lesson rather than a finding**: registration must require an authenticated session.

#### payload-oauth2 (WilsonLe)

Source: [source](https://github.com/WilsonLe/payload-oauth2) at HEAD, fetched 2026-11-06.

- **Approach:** it modifies the auth collection in place. It adds a custom strategy plus authorise and callback endpoints on the collection (`/api/users/oauth/<provider>`).
- **Token issue:** on callback it reproduces Payload's login. It writes its own Payload session onto `user.sessions` (`auth-sessions.ts` re-implements `addSessionToUser`), builds claims with `getFieldsToSign({ collectionConfig, email, sid, user })`, signs with `jose` `SignJWT` (`{ alg: 'HS256' }` only, **no `authVersion` header**) and sets the cookie with `generatePayloadCookie`. It also runs the collection's `afterLogin` hooks by hand.
- **Why it still works after 3.90:** its own strategy verifies HS256 tokens signed with `payload.secret` itself, rather than relying on `local-jwt`. **Inference from source, not tested.**
- **Lesson:** the safer approach is Payload's exported `jwtSign`, which adds `authVersion`.

### 5.4 Payload's built-in auth surface (what a passkey/PIN plugin can build on)

Docs fetched from the `3.x` branch on 2026-11-06: [overview](https://github.com/payloadcms/payload/blob/3.x/docs/authentication/overview.mdx), [custom-strategies](https://github.com/payloadcms/payload/blob/3.x/docs/authentication/custom-strategies.mdx), [cookies](https://github.com/payloadcms/payload/blob/3.x/docs/authentication/cookies.mdx), [jwt](https://github.com/payloadcms/payload/blob/3.x/docs/authentication/jwt.mdx), [token-data](https://github.com/payloadcms/payload/blob/3.x/docs/authentication/token-data.mdx), [operations](https://github.com/payloadcms/payload/blob/3.x/docs/authentication/operations.mdx), [api-keys](https://github.com/payloadcms/payload/blob/3.x/docs/authentication/api-keys.mdx). These mirror payloadcms.com/docs/authentication/*. Source quotes are from `packages/payload/src/auth/*` on `3.x` (3.93.0).

#### Collection `auth` options relevant here

| Option | Notes (docs, fetched 2026-11-06) |
|---|---|
| `tokenExpiration` | Seconds; "JWTs and HTTP-only cookies will both expire at the same time". It also sets each session's `expiresAt`. |
| `useSessions` | "True by default. Set to `false` to use stateless JWTs … Stateless JWTs cannot be revoked." |
| `strategies` | "an array of custom authentication strategies to extend this collection's authentication with". |
| `disableLocalStrategy` | "Only use this property if you have replaced Payload's auth mechanisms with your own." Important: `local-jwt` *rejects* tokens for such collections (see below). |
| `maxLoginAttempts` / `lockTime` | Built-in lockout. Exported helpers `incrementLoginAttempts` and `resetLoginAttempts` (from `payload`) let a plugin reuse it for PIN attempts. |
| `loginWithUsername` | `true` or `{ allowEmailLogin, requireEmail }`. |
| `useAPIKey` | Per-user API keys. Since 3.90 keys are shown once, omitted from reads, and encrypted with the secret. Changing a password does not disable a key. |
| `cookies` | `secure`, `sameSite`, `domain`. |
| `depth`, `removeTokenFromResponses`, `verify`, `forgotPassword` | as documented |
| root `auth.passwordHashIterations` | Added 3.x (commit 2026-10-29, #19074); PBKDF2 defaults to 600,000 iterations. |

#### Custom strategy contract

From the custom-strategies doc and `auth/types.ts`:

```ts
type AuthStrategy = { name: string; authenticate: AuthStrategyFunction }
type AuthStrategyFunctionArgs = {
  canSetHeaders?: boolean   // whether response headers can be set in this context
  headers: Request['headers']
  isGraphQL?: boolean
  payload: Payload
  req?: PayloadRequest      // "The request that initiated authentication, when available"
  strategyName?: string
}
type AuthStrategyResult = {
  responseHeaders?: Headers
  user: ({ _strategy?: string; collection?: string } & TypedUser) | null
}
```

- **Return value:** `authenticate` must return `{ user: { collection: '<slug>', ...userDoc } | null, responseHeaders? }`. The doc example: "Send the user with the collection slug back to authenticate, or send null if no user should be authenticated".
- **Order:** custom strategies run first, in collection order. The API-key strategy comes next, and `local-jwt` is pushed **last** (`payload/src/index.ts`, `this.authStrategies = …; // 4. if enabled, push jwt strategy into authStrategies last`). `executeAuthStrategies` returns the first result with a `user`, catches and logs thrown errors, and merges `responseHeaders`.
- **Dev note:** "Changes to custom authentication strategies require a full server restart … not hot-reloaded".

#### What `req.user` looks like

It is the full user document (depth `auth.depth`, default 0) with these additions:

- `collection` (slug)
- `_strategy` (for example `'local-jwt'`, or the custom strategy's `name`)
- `_sid` (the current session ID when `useSessions` is on, set by `JWTAuthentication`)

Fields with `saveToJWT` are also in the token. Since the 3.90 security work, JWT keys `id`, `collection`, `email`, `sid`, `iat` and `exp` are reserved, and a `saveToJWT` alias cannot override them (token-data doc). In custom views, the top-level `user` prop is read-filtered; `initPageResult.req.user` is the full server principal (custom-views doc).

#### How Payload issues its JWT and cookie

The `login` operation (`auth/operations/login.ts`) runs these steps:

1. Verify the password and the lock (`isUserLocked`, `incrementLoginAttempts`).
2. `getFieldsToSign({ collectionConfig, email, user, sid? })`.
3. `addSessionToUser({ collectionConfig, payload, req, user })`. When `useSessions` is on, this pushes `{ id: uuid(), createdAt, expiresAt: now + tokenExpiration }` into `user.sessions`, prunes expired ones, and saves with `payload.db.updateOne` (`updatedAt` untouched). It returns `{ sid }`.
4. `resetLoginAttempts`.
5. Collection `beforeLogin` hooks.
6. `jwtSign({ fieldsToSign, secret, tokenExpiration })`.
7. `afterLogin` hooks, with `token`.
8. `afterOperation`.
9. On error, `revokeSession`.

The REST and GraphQL handlers then set the cookie. `payload.login({ collection, data: { email, password } })` (Local API) needs a password, so a passwordless plugin has to replicate the steps above itself.

`jwtSign` (`auth/jwt.ts`) signs HS256 with protected header `{ alg: 'HS256', authVersion: JWT_AUTH_VERSION, typ: 'JWT' }`. `payload.secret` is the *processed* secret: SHA-256 of `PAYLOAD_SECRET`, hex, first 32 chars (jwt doc).

**Breaking in 3.90.0 (2026-09-18):** `JWTAuthentication` throws unless `protectedHeader.authVersion === JWT_AUTH_VERSION`. It also rejects a token whose `collection` isn't a string, whose `id` isn't a string or number, or whose `sid` is present but not a string. And it throws "JWT authentication requires an auth-enabled local collection" if the collection has `disableLocalStrategy`. `jwtAuth.ts` is absent at tag `v3.89.0` and present at `v3.90.0`. The token-data doc says: "Tokens issued before this protection was added do not have the marker and must be replaced by signing in again". [UPDOT #160](https://github.com/UPDOT/payload-auth-plugin/issues/160) shows a plugin that minted its own tokens breaking on this change.

With `useSessions`, `local-jwt` also requires `user.sessions` to contain the token's `sid`; otherwise `user: null`. **That array is the revocation mechanism.**

The cookie (`auth/cookies.ts`, `generatePayloadCookie({ collectionAuthConfig, cookiePrefix, token, returnCookieAsObject? })`):

- **Name:** `${cookiePrefix}-token`, with the default prefix `payload`, so `payload-token`.
- **Attributes:** `HttpOnly`, `Path=/`; `Expires` from `tokenExpiration`; `SameSite` from `auth.cookies.sameSite` (a boolean `true` means `Strict`); `Secure` and `Domain` from config.
- **Logout cookie:** `generateExpiredPayloadCookie` makes the logout cookie.

Cookie extraction (`extractJWT`, order `auth.jwtOrder` default `['JWT', 'Bearer', 'cookie']`) checks CSRF:

- With an `Origin` header, the cookie is used only if `config.csrf` is empty or contains the origin.
- Without `Origin`, but with a `csrf` list, it falls back to `Sec-Fetch-Site` (`same-origin`, `same-site` or `none`).

Exports usable by a plugin (3.93.0):

| Import | Symbols |
|---|---|
| `payload` | `jwtSign`, `JWT_AUTH_VERSION`, `getFieldsToSign`, `executeAuthStrategies`, `extractJWT`, `incrementLoginAttempts`, `resetLoginAttempts`, `addDataAndFileToRequest`, `headersWithCors`, `createPayloadRequest`, `definePlugin`, `baseSessionsField`, and (through `export * from './auth/index.js'`) `generatePayloadCookie`, `generateExpiredPayloadCookie`, `parseCookies`, `getCookieExpiration` plus all auth types |
| `payload/shared` | `addSessionToUser`, `removeExpiredSessions`, the cookie helpers again, `getLoginOptions` |

`revokeSession` is **not** exported. A plugin removes a session by filtering `user.sessions` and saving with `payload.db.updateOne`, as Payload does. Exports not listed in the docs count as "undocumented exports" under the [versioning policy](https://github.com/payloadcms/payload/blob/main/docs/migration-guide/versioning.mdx) (v4 docs, fetched 2026-11-06) and may change in a minor release. **Flag:** `jwtSign`, `getFieldsToSign` and `addSessionToUser` are not in the docs prose.

#### Sessions: storage and revocation

- **Storage:** sessions are stored **on the user document** as a `sessions` array field (`auth/baseFields/sessions.ts`: `{ id: text required, createdAt: date, expiresAt: date required }`). It is `admin.disabled`, `update: () => false`, and readable only by the user themself.
- **Logout:** ends the current session; `?allSessions=true` ends all of them (operations doc).
- **Password changes** (3.90, "Password changes now revoke other sessions"):
  - changing your own password keeps the current session and ends the rest;
  - an admin changing someone else's ends all of that user's sessions;
  - `resetPassword` ends all sessions and creates a new one;
  - a Local API update without `user` ends all sessions.
- **Payload 4 beta:** sessions also gain `refreshCount` and `refreshedAt` for refresh tokens. MongoDB needs no migration ([v4 migration guide](https://github.com/payloadcms/payload/blob/main/docs/migration-guide/v4.mdx), fetched 2026-11-06).

#### Using `payload.auth({ headers })` from a plugin endpoint

`payload.auth({ headers, canSetHeaders?, req? })` (`auth/operations/local/auth.ts`) runs every strategy and returns `{ user, permissions, responseHeaders }`.

Inside a custom endpoint it is usually unnecessary: Payload has already authenticated the request, so `req.user` is populated. The REST doc warns "Custom endpoints are not authenticated by default. You are responsible for securing your own endpoints"; that is, the handler must check `req.user` itself. `payload.auth` is useful in Next route handlers and server components outside `/api`. The operations doc shows passing its `user` into `payload.update` so a password change keeps the current session.

#### Admin login screen: extension points

From the [root-components doc](https://github.com/payloadcms/payload/blob/3.x/docs/custom-components/root-components.mdx), the [custom-views doc](https://github.com/payloadcms/payload/blob/3.x/docs/custom-components/custom-views.mdx) and the `packages/next/src/views/Root/*` source (3.x, fetched 2026-11-06):

| Hook | What it does |
|---|---|
| `admin.components.beforeLogin` / `afterLogin` | Arrays of components rendered before or after the built-in login form. This is the least invasive place for a "Sign in with a passkey" button, as payload-passkey does with `afterLogin`. |
| `admin.components.logout.Button` | Replaces the sidebar logout button. |
| `admin.components.providers` | Client context wrapping the whole admin ("must include the `use client` directive"). |
| `admin.components.views.<key>` | The docs list only `account`, `dashboard` and new `[key]` views. In source, `getRouteData.ts` checks `getCustomViewByKey({ config, viewKey })` for any key of `admin.routes` (`login`, `logout`, `forgot`, `createFirstUser`, `inactivity`, `unauthorized`, `account`, `browseByFolder`) **before** the built-in view. So `views.login = { Component: 'pkg/rsc#Login' }` replaces `/admin/login` and keeps the minimal template. This came from [PR #14066](https://github.com/payloadcms/payload/pull/14066) (merged 2025-10-10, "Fixes the ability to override built-in single-segment admin views (like `create-first-user`, `login`, `account`, etc.)"). **It is undocumented, so treat it as fragile.** |
| `admin.routes.login` (and the other `admin.routes.*`) | Changes the path Payload binds each built-in view to (defaults: `/login`, `/logout`, `/logout-inactivity`, `/forgot`, `/reset`, `/create-first-user`, `/unauthorized`, `/account`). payload-auth sets `routes.login` to `/login-redirect` and serves its own `/login` view. |
| New views at a custom `path` | "All Custom Views are public by default". `RootPage` skips the auth redirect for `isCustomAdminView` routes, so the view must check `initPageResult.req.user` itself. |

On public routes: `isPublicAdminRoute` treats any route that **starts with** a public segment (`/login`, `/logout`, `/forgot`, `/reset`, `/create-first-user`, `/logout-inactivity`, `/unauthorized`, or `/<authCollection>/verify/<token>`) as reachable without admin access. This uses `startsWith`, so `/login-pin` counts as public too. **Inferred from the source, not documented.**

`admin.autoRefresh: true` keeps admin tokens fresh. The `refresh` operation (`POST /api/<users>/refresh-token`) re-signs the token and the cookie.

---

## 6. How other CMSs do it

Research date: 2026-11-06. Version numbers and dates come from the linked pages or source as fetched that day.

### 6.1 Summary table

| CMS | Built-in 2FA | Passkeys | Recovery | Step-up / elevated session | Admin reset of a locked-out user |
|---|---|---|---|---|---|
| **Craft CMS 5** | TOTP + recovery codes (since 5.0.0, 2024-03-26); enforce per user group | **Yes, native, passwordless** (control panel; front end since 5.6) | 10 codes, `xxxxxx-xxxxxx` | **Yes**: `elevatedSessionDuration` default 300 s | CLI `craft users/remove-2fa <user> [--method]` (5.5.0) |
| **Statamic 6** | TOTP + recovery codes in core (6.0.0, 2026-01-28); `two_factor_enforced_roles` | **Yes, native** (6.0.0) | Single-use recovery codes | **Yes**: `elevated_session_duration` 15 min; password, passkey or email code | Disable form deletes codes; enforced users are sent to set-up |
| **WordPress** (core) | None in core as of 7.1 | None in core | — | — | — |
| **WordPress "Two Factor" plugin** | TOTP, email, backup codes | Via the companion "WebAuthn Provider for Two Factor" plugin | 10 single-use codes, low-codes warning | **Yes**: re-validate 2FA before changing 2FA settings (10 min view / 20 min save) | User-edit screen; WP-CLI `wp two-factor disable` (0.17.0) |
| **Ghost** | Email code on new device (default on); optional email code on every login | No (forum request only) | Email only; Ghost(Pro) support | — | Config `security.staffDeviceVerification: false` |
| **Directus** | TOTP; "Require 2FA" per policy | Not documented | Not documented | Password needed to generate the TOTP secret | Not documented on the 2FA page |
| **Strapi 5** | **None** for local admin accounts | None | — | — | SSO (Enterprise / Growth add-on) or a proxy |
| **Sanity** | Delegated to the login provider (Google, GitHub, SAML) | Not native (via the IdP) | Via the IdP | — | Via the IdP |
| **Kirby** | Email code or TOTP (TOTP since 4.0) | Not in core | Not documented | Password needed to turn TOTP off | Not documented |
| **Umbraco 17** | Pluggable `ITwoFactorProvider` (TOTP sample); MFA via Umbraco ID on Cloud | No provider documented (custom views allow one) | Not documented | Disabling needs a code | Not documented on the page |

### 6.2 WordPress

**Core.** No 2FA or passkeys in WordPress core as of 7.1 (third-party blogs fetched 2026-11-06, e.g. https://www.pb4host.com/wordpress-two-factor-authentication-in-2026-complete-guide-to-secure-logins/). The Two Factor plugin's recovery roadmap issue #909 (https://github.com/WordPress/two-factor/issues/909, opened 2026-06-14) was added to and then **removed from the "Core Merge Proposal" milestone on 2026-09-25**. Flag: there may be core discussion this didn't find. Core's closest lock-screen feature is the **interim login modal** (`wp_auth_check`, WP 3.6, https://developer.wordpress.org/reference/functions/wp_auth_check/). The Heartbeat notices an expired session and shows a login box over the page, so unsaved editor work survives re-login.

**"Two Factor" plugin** (https://wordpress.org/plugins/two-factor/, fetched 2026-11-06; maintained under the WordPress GitHub org, https://github.com/WordPress/two-factor):

- 0.17.0 (2026-09-25 rc, 2026-09-28 GitHub release), 100,000+ active installs, **requires WP 7.0+**, PHP 7.4+, tested to 7.1.4.
- Providers: TOTP and backup codes (both "recommended"), email codes (expire after 15 min, `two_factor_token_ttl`, since 0.6.0) and a debug-only Dummy. **FIDO U2F was removed in 0.16.0 (2026-03-27)** because browsers dropped U2F. Passkeys come from the companion plugin; native WebAuthn is an open issue.
- Backup codes: **10 by default, single use**, 8 characters (`two_factor_backup_code_length`), downloadable. 0.11.0 (2025-01-09) "encourage setting up a second recovery method"; 0.17.0 "early notice for soon exhausting recovery codes" (#907).
- **Revalidation / sudo (0.9.0, 2024-04-25):** "Users are now asked to re-authenticate with their two-factor before making changes to their two-factor settings" (#529). The session records when 2FA last happened (#528). From source (`class-two-factor-core.php`, master, fetched 2026-11-06): `apply_filters('two_factor_revalidate_time', 10 * MINUTE_IN_SECONDS, $user_id, $context)`, doubled for `'save'`. `0` disables it. A revalidate URL takes `interim-login` for the modal flow, and revalidate POSTs need a nonce (#575). 0.10.0 fires an action on revalidation.
- **Activating 2FA destroys the user's other sessions** (0.9.0, #578). Login nonces last 10 minutes. Rate limiting since 0.8.0, capped by `two_factor_max_rate_limit` (15 min).
- **0.17.0 security fix: "regular passwords could bypass 2FA for REST API and XML-RPC requests."** Since 0.14.0, Application Passwords are the API credential.
- Locked-out users: an admin unticks the methods on the user's profile, or uses WP-CLI (0.17.0) `wp two-factor disable <user> [--yes]`, `wp two-factor unlock <user>` (clears the throttle only) and `wp two-factor status <user>`. Filters `two_factor_is_required_for_user` and `two_factor_providers_for_user` (0.13.0). **No built-in enforcement by role** (issue #255). Issue #909 lists the unsolved case: a single-admin site with no second admin, where "self-service recovery … is not technically possible without compromising the very promise of the second factor" (kasparsd, #621). Proposals include a `wp-config.php` bypass for one named account (#908).

**"WebAuthn Provider for Two Factor"** (https://wordpress.org/plugins/two-factor-provider-webauthn/, fetched 2026-11-06): 2.6.2 (updated 2026-10-15), 2,000+ installs, by Volodymyr Kolesnykov. WebAuthn and passkeys as a **second factor, not passwordless**; optional key names; registration and sign-in attempts expire after 10 minutes. Last-used is not mentioned.

**Passkey plugins on WordPress.org** (plugin API search "passkey", fetched 2026-11-06): Wordfence (5 M; TOTP 2FA), Really Simple Security (3 M), WP 2FA (100 k), FluentAuth (10 k; "passkeys, social login, magic login"), miniOrange 2FA (10 k; passkey), Secure Passkeys (2 k, 1.3.0 2026-07-01, passwordless), WP-WebAuthn (2 k, 1.4.1 2026-04-15, passwordless), Advanced Passkeys (40). Passkeys on WordPress remain fragmented and low-install, and none is "official". Not checked: Corbado's plugin and Jetpack / WordPress.com.

**WordPress.org accounts:** 2FA for wordpress.org accounts went into beta in May 2023 with TOTP, **security keys (default over TOTP)** and backup codes (WP Tavern, 2023-09-26, https://wptavern.com/wordpress-org-expands-two-factor-authentication-interface-to-include-security-keys; project `wporg-two-factor`). **Mandatory for plugin and theme committers from 2024-10-01** (https://make.wordpress.org/plugins/2024/09/04/upcoming-security-changes-for-plugin-and-theme-authors-on-wordpress-org/), alongside separate SVN passwords. The guidance stresses printing backup codes, because losing the key without codes can mean losing the account. Whether wordpress.org now offers passwordless passkey login was not confirmed (flag).

### 6.3 Strapi 5

No built-in second factor for local admin accounts: "Strapi does not ship a built-in TOTP second factor for local admin accounts" (Strapi blog, 2026-09-09, https://strapi.io/blog/strapi-admin-panel-mfa-2fa). The official route is SSO (Enterprise, or the Growth add-on) with MFA at the IdP, keeping **one local Super Admin as a break-glass account**, or putting `/admin` behind Cloudflare Access, a VPN, Tailscale or oauth2-proxy. The post also advises shorter `admin.auth.sessions` lifetimes and session review and revocation. Community plugins: Strapi Identity (TOTP, v5), `@vivinkv28/strapi-2fa-admin-plugin` (email OTP, release 2026-04-06), HeadLockr (TOTP, SMS, email, backup codes; passkeys "on the roadmap") (https://market.strapi.io/, fetched 2026-11-06). The blog warns that admin auth internals changed between v4 and v5, so v4 plugins break. **Lesson for Payload:** the plugin should hook public auth extension points, not internals, and test on each Payload minor.

### 6.4 Directus

TOTP from any authenticator app or OTP-capable password manager. **Generating the secret requires the current password**; set-up is finished by submitting the secret plus a current OTP; disabling needs only an OTP. "Require 2FA" is a **policy** setting (enforced if any of the user's policies has it, with an IP-allowlist nuance), and users without 2FA are sent to set-up after login, SSO included (https://directus.com/docs/guides/auth/2fa, fetched 2026-11-06, no page date). Recovery codes, admin reset and passkeys are not documented there (flag).

### 6.5 Craft CMS 5 (the closest analogue)

Sources: https://craftcms.com/docs/5.x/system/user-management.html and https://craftcms.com/docs/5.x/reference/config/general.html (fetched 2026-11-06); source at https://github.com/craftcms/cms/tree/5.x; CHANGELOG (fetched 2026-11-06).

- **Shipped in 5.0.0 (2024-03-26):** TOTP 2FA, recovery codes and **passwordless passkeys** for the control panel. Server: `web-auth/webauthn-lib` with attestation `none` only. Client: **`@simplewebauthn/browser`** (`ElevatedSessionManager.js` imports `browserSupportsWebAuthn` and `platformAuthenticatorIsAvailable`).
- **Passkey storage** (`m230314_111234_add_webauthn_table.php`): `userId`, `credentialId`, `credential` (serialised source), **`credentialName`**, **`dateLastUsed`**, `dateCreated`, `dateUpdated`, `uid`. The My Account → Passkeys table shows **Name | Last Used | delete** (`_passkeys-table.twig`). Users can hold several passkeys and revoke any of them.
- **Enrolling a passkey asks for the password**, plus the current TOTP code if 2FA is on (CraftQuest, https://craftquest.io/articles/2fa-and-passkey-support-in-craft-cms-5). The "Password & Verification" and "Passkeys" pages are hidden for users without a password (5.5/5.6 era changelog).
- **Recovery codes** (`src/auth/methods/RecoveryCodes.php`): `setCount(10)`, 2 blocks of 6 mixed-case characters (`abcdef-GHIJKL`), each used code replaced by `false`. **They are stored as plain JSON, not hashed:** a lesson to do better.
- **Enforcement:** "Require two-step verification" per user group (Settings → Users → Security), which applies to all matching users since 5.6. `disable2fa` / `CRAFT_DISABLE_2FA` for development (5.6.0). Admins can't manage another user's 2FA in the UI, but **`craft users/remove-2fa <user>`** exists (5.5.0) with `--method`.
- **Elevated sessions:** `elevatedSessionDuration` default **300 s**, `0` disables it. Required for "sensitive actions, such as user group or permission assignment", removing auth methods, GraphQL schemas, **user impersonation** (5.5.0) and **deleting a passkey** (5.11.4, 2026-10-01). The client asks the server for the remaining time (`users/get-elevated-session-timeout`); if less than `minSafeElevatedSessionTimeout` (5 s) remains, it opens a **login modal over the current page**, where the passkey button appears if the user has passkeys (`showPasskeyBtn: Craft.userHasPasskeys`), then runs the original action. When impersonating, elevation checks the original user (5.5.0).
- **Session expiry / lock pattern:** `userSessionDuration` default 3600 s idle; `rememberedUserSessionDuration` 14 days. `Craft.AuthManager` polls the remaining session time, shows "Your session will expire in {time}" with **"Keep me signed in"**, then a re-login modal without leaving the page.
- **Other hardening:** setting up 2FA destroys the user's other sessions (5.11.4). `.well-known/passkey-endpoints` support (5.11.0, 2026-09-01). Rate limits on `users/login`, `auth/verify-totp` and `auth/verify-recovery-code`, with `defaultRateLimit` / `defaultRateLimitDuration` (5.12.0, 2026-11-03; docs say 10 a minute per IP). Non-standard `ED256` removed (5.12.0). Failed 2FA attempts count towards the lockout limit.
- **Security incidents to learn from:**
  - **GHSA-wg23-69c2-gjc8 (2026-08-07, CVSS 9.1 Critical), fixed in 5.10.5:** "Passkey login accepts replayed WebAuthn assertions". `users/login-with-passkey` took the `requestOptions`, and so the **challenge, from the unauthenticated request body**, and **didn't save the new counter**, so a captured request could be replayed for a fresh session (https://advisories.gitlab.com/composer/craftcms/cms/GHSA-wg23-69c2-gjc8/).
  - Verification codes could be reused in 5.0.0 to 5.10.x (fixed 5.11.0, per search results; flag: detail not fetched).
  - A bug let 2FA set-up proceed without re-authentication when an elevated session already existed (CHANGELOG #18753).

### 6.6 Statamic 6

Statamic 6.0.0 (2026-01-28) moved 2FA into core and added **passkeys and elevated sessions** (https://statamic.com/release-notes, https://laravel-news.com/statamic-6-is-officially-released; the sneak peek is dated 2025-07-15). From `config/users.php` and `config/webauthn.php` on the 6.x branch (fetched 2026-11-06):

- `elevated_sessions_enabled` (env `STATAMIC_ELEVATED_SESSIONS_ENABLED`, default true), **`elevated_session_duration` = 15 minutes**, `elevated_sessions_url`.
- Elevation method per user: `password_confirmation`, or **`verification_code` (emailed) for users without a password**; a passkey is offered when the user has one (`ElevatedSessionController`: `allowPasskey => $method !== 'verification_code' && $user->passkeys()->isNotEmpty()`).
- `two_factor_enabled`, **`two_factor_enforced_roles`** (`'*'` or `'super_users'`), front-end challenge and set-up URLs. Single-use recovery codes; disabling 2FA deletes them, and users in enforced roles are sent back to set-up (https://statamic.dev/tags/user-two_factor_recovery_codes).
- `webauthn.allow_password_login_with_passkey` (default true): **whether a user who has a passkey may still sign in with a password**. `webauthn.remember_me`. The Passkey contract has `name()` and **`lastLogin()`**.
- **CVE-2026-27939 / GHSA-rw9x-pxqx-q789 (published 2026-02-27, CVSS 8.8), fixed in 6.4.0:** "Privilege escalation via elevated session bypass": control panel users could gain elevated privileges "under certain conditions" without verifying.

### 6.7 Ghost

Since 2025-04-22 (https://ghost.org/changelog/2fa/), **staff device verification** sends a 6-digit email code on a new or unrecognised device and is on by default. Admins can also require an email code on every staff login (Settings → Staff → Security). Self-hosters can turn device verification off with `security.staffDeviceVerification: false` (https://docs.ghost.org/config/, fetched 2026-11-06). There is no TOTP or passkey; passkeys are an open forum request. Ghost recommends Cloudflare Access with SSO for stricter needs. Recovery when email fails is support-led on Ghost(Pro), and forum threads report lock-outs when mail doesn't arrive. The exact Ghost version wasn't stated (flag; April 2025 is in the 5.x line).

### 6.8 Sanity

Studio login goes through Sanity accounts (Google, GitHub, email) or SAML SSO (Enterprise, or the Growth add-on, https://www.sanity.io/docs/sso-saml). 2FA is the login provider's job (https://www.sanity.io/answers/clarification-on-two-factor-authentication-for-microsoft-users, updated 2025-11-29). No native Sanity passkeys were found (flag).

### 6.9 Kirby

Built-in email-code 2FA, plus TOTP since Kirby 4 (`Kirby\Toolkit\Totp`, 4.0.0-beta.3; https://getkirby.com/releases/4.0/totp). Users turn TOTP off **by entering their password**. Other methods come from auth-challenge plugins (https://getkirby.com/docs/guide/authentication/2fa, fetched 2026-11-06; the site promotes Kirby 6 Beta 3). No core passkeys: staff said "maybe later" in the forum thread https://forum.getkirby.com/t/plans-to-support-proper-2fa-such-as-fido-or-passkeys/29502, and the community `k3-fido2` targets Kirby 3. Recovery codes are not documented.

### 6.10 Umbraco

An `ITwoFactorProvider` abstraction for backoffice users and members, registered as an `mfaLoginProvider` in `umbraco-package.json`; the docs' sample uses the GoogleAuthenticator NuGet package. Users enable it through Avatar → Configure Two-Factor, and disabling requires a code. Login and activation screens can be replaced with custom views, the route for a non-code (WebAuthn) provider. Umbraco Cloud uses Umbraco ID MFA (https://docs.umbraco.com/umbraco-cms/17.latest/run-in-production/security/two-factor-authentication, fetched 2026-11-06). No passkey provider, enforcement or recovery codes are documented (flag).

### 6.11 Lessons for a Payload passkey + PIN plugin

**Ceremony and server security**

1. **Issue the challenge on the server, store it there (or in a signed, short-lived cookie), and use it once.** Never accept options or a challenge from the client. Craft's critical CVE came from exactly this.
2. **Save `newCounter` and `dateLastUsed` after every successful assertion**, in the same write. Treat a counter that goes backwards as a failure (SimpleWebAuthn already throws).
3. **Gate every login path, not just the admin UI.** WordPress Two Factor 0.17.0 fixed passwords that bypassed 2FA over REST and XML-RPC. For Payload that means `POST /api/<users>/login`, GraphQL `login<Users>`, `refresh-token`, `forgot-password`/`reset-password` (which logs in), API keys (`useAPIKey`) and the Local API. Decide what the PIN or passkey protects and enforce it in a `beforeLogin`/`afterLogin` hook or a custom strategy, not only in a React view.
4. **Rate-limit PIN, TOTP and recovery-code checks and count them towards lockout** (Craft 5.12; WP Two Factor rate limits capped at 15 min). A PIN is low-entropy: lock after a few attempts, and hash it with a slow KDF (Payload already uses pbkdf2 for passwords).
5. **Hash recovery codes** (Craft stores them in plain JSON; don't). Show them once, allow download, warn when few remain (WP Two Factor 0.17.0), and regenerate them as a step-up action.
6. **Destroy the user's other sessions when a factor is added or removed** (WP Two Factor 0.9.0, Craft 5.11.4).
7. **Require user verification** (`userVerification: 'required'` plus `requireUserVerification: true`) when a passkey stands in for password plus second factor.

**Step-up ("sudo")**

8. Copy the Craft/Statamic/WP pattern: a **short elevated window** (Craft 5 min, WP 10 min to view and 20 to save, Statamic 15 min). It covers adding or deleting a passkey, changing the PIN, regenerating recovery codes, removing another user's factors, changing roles, and creating API keys. **Show the prompt as a modal over the current page and then run the original action**, as Craft does. Offer every method the user has: passkey, password, and an email code for users without a password, as Statamic does.
9. **Enrolling the first passkey needs a fresh password or step-up** (Craft, Directus, Better Auth `requireSession: true`). Test the "already elevated" path: Craft once let set-up skip re-authentication there (#18753).
10. Statamic's elevated-session bypass CVE (8.8) shows that **step-up must be checked on the server for each sensitive endpoint**, not just shown by the UI.

**Management UI**

11. **List passkeys with name, created date, last used and a synced/device-bound badge** (from `credentialBackedUp`/`credentialDeviceType`), with rename and delete. **Default the name from the AAGUID** (provider name, e.g. "iCloud Keychain", "Google Password Manager"), falling back to the user agent; this is web.dev's guidance (https://web.dev/articles/passkey-management, 2025-05-15) and Craft's and Statamic's practice.
12. **Warn before deleting the last passkey** and offer another method first (web.dev). After a delete or rename, call `sendSignal({ signalName: 'allAcceptedCredentials' | 'unknownCredential' … })` so password managers stop offering dead passkeys.
13. Let a user register **several passkeys from different providers** as a recovery path.
14. Make "may a passkey user still sign in with a password?" a setting, like Statamic's `allow_password_login_with_passkey`.

**Recovery and admin reset**

15. Give admins a **reset for another user** (WP: tick-boxes on the profile; Craft and WP: CLI). In Payload: an admin-only action on the user document, behind step-up, plus a **server-side bin script** for the single-admin case (WP #909's unsolved gap). A Payload `bin` script or `payload run` script fits.
16. Follow WP #909: **no site-wide "disable for everyone" switch.** Offer an env-var escape hatch for one named account, like WP proposal #908 and Craft's `CRAFT_DISABLE_2FA` (which is global, for development only). Any self-service recovery should be opt-in and deliberately slow.
17. Keep a **break-glass local admin** (Strapi's advice when SSO is primary) and document it.
18. Enforce **by role or group, not per user** (Craft by group, Statamic `two_factor_enforced_roles`, Directus by policy). WP Two Factor's lack of enforcement is its most-requested gap (#255).

**Lock screen / idle**

19. No CMS surveyed has a PIN lock screen. The closest patterns are Craft's AuthManager ("Your session will expire in {time}", "Keep me signed in", then a re-login modal over the page) and WordPress's interim login modal (`wp_auth_check`, which keeps unsaved editor content). **Lock in place: a modal over the current view, not a redirect**, so autosaved drafts and form state survive. Unlock with the PIN or a passkey, and fall back to a full login after N failures.
20. Keep the idle-lock timer separate from Payload's JWT expiry (`tokenExpiration`). A lock should hide the UI and block writes until unlocked; it doesn't have to end the session. Make the server enforce the "locked" state too (point 3), or the lock is cosmetic.
21. Plan for email being unreliable when an email code is a fallback (Ghost lock-out threads), and allow device-memory opt-out by config like Ghost's `staffDeviceVerification`.

---

## 7. Payload plugin authoring best practice

Sources fetched 2026-11-06:

- [plugins/overview](https://github.com/payloadcms/payload/blob/3.x/docs/plugins/overview.mdx)
- [plugins/build-your-own](https://github.com/payloadcms/payload/blob/3.x/docs/plugins/build-your-own.mdx)
- [plugins/plugin-api](https://github.com/payloadcms/payload/blob/3.x/docs/plugins/plugin-api.mdx)
- [custom-components/overview](https://github.com/payloadcms/payload/blob/3.x/docs/custom-components/overview.mdx)
- [rest-api/overview § Custom Endpoints](https://github.com/payloadcms/payload/blob/3.x/docs/rest-api/overview.mdx)
- [troubleshooting](https://github.com/payloadcms/payload/blob/3.x/docs/troubleshooting/troubleshooting.mdx)
- the official template at [`templates/plugin` on 3.x](https://github.com/payloadcms/payload/tree/3.x/templates/plugin)

These mirror payloadcms.com/docs/plugins/*. The template on `main` (v4 beta) is still the same plain-function shape, with peer `payload ^3.82.1`.

### 7.1 Plugin shape: receiving and returning config

**The basic contract**, which the docs say is permanent: "a plugin is a function that receives a config and returns a modified config. That simplicity is intentional and permanent". The build-your-own doc pattern:

```ts
export const samplePlugin = (pluginOptions) => (incomingConfig: Config): Config => {
  let config = { ...incomingConfig }
  config.collections = [...(config.collections || []), newCollection]
  config.onInit = async (payload) => {
    if (incomingConfig.onInit) await incomingConfig.onInit(payload)   // chain, never replace
    // plugin init
  }
  return config
}
```

**Spreading and chaining.** Spread arrays and objects such as `collections`, `globals`, `hooks` and `admin`. Function properties can't be spread, so call the incoming function and then add yours. payload-totp chains `await config.onInit?.(payload)` after its own work. Collection hooks are chained the same way, for example `afterLogout: [...(collection.hooks?.afterLogout || []), mine]`.

**Init order** (docs): 1) incoming config is validated, 2) plugins execute, 3) defaults are integrated, 4) sanitisation, 5) final config is initialised. A plugin therefore sees *unsanitised* config: `auth` may be `true` rather than an object, and `admin.components.*` may be undefined. Normalise before writing, as in `typeof collection.auth === 'object' ? collection.auth : {}`. Payload appends some collections *after* all plugins run (jobs, locked-documents, query presets, folders); payload-totp patches those in `onInit`.

**Enable or disable.** The docs say "provide a way to disable the plugin without uninstalling it". The template uses `disabled?: boolean`, while the docs' example uses `enabled`. The template's guidance is that when disabled it "still want[s] to keep added collections/fields so the database schema is consistent which is important for migrations". payload-totp follows this: it keeps `totpSecret` and the `totp-attempts` collection, and adds no strategy, views, endpoints, hooks or access wrappers.

**`definePlugin` (experimental).** Added in [v3.83.0](https://github.com/payloadcms/payload/releases/tag/v3.83.0) (2026-04-15, PR #16247) and marked `@experimental`:

- **Signature:** `definePlugin<TOptions>({ slug, order, plugin: ({ config, plugins, ...options }) => Config })`.
- **`order`:** lower values run first; the default is 0. The suggested convention is "100+ Must run last". An access-wrapping auth plugin would want to run last, as payload-totp tells users to do by hand.
- **`plugins` map:** slug-keyed. `declare module 'payload' { interface RegisteredPlugins { 'my-slug': Opts } }` types cross-plugin discovery.
- **In Payload 4** ([v4 guide](https://github.com/payloadcms/payload/blob/main/docs/migration-guide/v4.mdx)), `slug` becomes required and options move under a named `options` argument (`plugin: ({ config, options }) => …`).

Recommendation: export the plain function. If `order` is wanted, set `pluginFn.slug` and `pluginFn.order` by hand or wrap `definePlugin` behind an internal adapter, because its signature changes in v4.

**Finding the users collection.** Use `config.admin?.user` (the slug that logs in to the admin). If unset, Payload provides a default `users` collection (admin overview doc). The plugin then finds `config.collections.find(c => c.slug === slug && c.auth)`, or takes a `collection` option, as payload-totp, payload-oauth2 (`authCollection`, default `'users'`) and payload-passkey (`userCollection`) all do. Throw a clear error if the collection is missing, as payload-oauth2 does. Add fields by spreading `fields: [...collection.fields, ...mine]`, and check for name clashes: payload-passkey throws on a conflicting field type.

### 7.2 Admin components: registration by import path

Components are referenced by **string path**, never imported into the config. That keeps server and client code out of the Node config, so the CLI still runs.

- **Template form:** `config.admin.components.beforeDashboard.push('plugin-package-name-placeholder/client#BeforeDashboardClient')` and `'…/rsc#BeforeDashboardServer'`.
- **Object form** (`PayloadComponent`): `{ path: 'pkg/rsc#Name', exportName?, serverProps?, clientProps? }`. payload-totp uses it, for example `{ path: 'payload-totp/rsc#TOTPSetup', serverProps: { pluginOptions } }`. `#Name` and `exportName` are interchangeable.
- **Secrets:** server props are serialised into the RSC payload. payload-auth strips `secret` and OAuth `clientSecret` before passing options as server props: "anything passed there is visible to anyone who loads the page".
- **Client components:** need `'use client'`. Non-serialisable default props are stripped automatically.
- **Extra imports:** `admin.dependencies` lets a plugin add entries to the import map that aren't referenced in a known location.

**Does the host need to regenerate the import map?** The docs say the map "is automatically regenerated at startup and whenever HMR runs", and also "Every time you start your development server or build your application". It is never regenerated at runtime or after a production build.

In practice the host's `importMap.js` is committed. A plugin that adds or changes component paths should tell users to run `payload generate:importmap` after install and upgrade; payload-auth's docs do. **This repo's CLAUDE.md already requires it after adding admin components.**

### 7.3 package.json exports, build and publishing

Official template (`templates/plugin/package.json`, 3.x, fetched 2026-11-06):

- **Module type:** `"type": "module"`, ESM only.
- **Dev exports:** `exports` points at **source** for development: `.` → `./src/index.ts`, `./client` → `./src/exports/client.ts`, `./rsc` → `./src/exports/rsc.ts`.
- **Published exports:** `publishConfig.exports` repoints them at `./dist/*.js` and `.d.ts`, with `main` and `types` likewise.
- **Files:** `"files": ["dist"]`. payload-totp adds `LICENSE`.
- **Scripts:**
  - `build`: `pnpm copyfiles && pnpm build:types && pnpm build:swc`
  - `build:swc`: `swc ./src -d ./dist --config-file .swcrc --strip-leading-paths`
  - `build:types`: `tsc --outDir dist --rootDir ./src` (the tsconfig has `emitDeclarationOnly: true`, `composite: true`, `module`/`moduleResolution: NodeNext`)
  - `copyfiles`: copies `src/**/*.{html,css,scss,ttf,woff,woff2,eot,svg,jpg,png,json}` to `dist`
- **`.swcrc`:** `jsc.target: esnext`, TypeScript and TSX parser, React `runtime: automatic`, `module.type: es6`, source maps on.
- **Imports:** relative imports must use `.js` extensions (NodeNext). The template does this, for example `'./endpoints/customEndpointHandler.js'`.
- **Peers and devs:** peer is `"payload": "^3.93.0"` only. devDependencies pin `payload`, `@payloadcms/next`, `@payloadcms/ui`, `@payloadcms/db-*` and `@payloadcms/richtext-lexical` to exactly `3.93.0`, with `next 16.3.3`, `react 19.2.6`, `typescript 5.7.3`, `vitest 4.0.18` and `@playwright/test 1.63.0`.
- **Engines:** `"node": "^22.23.4 || >=24.22.1"`, `"pnpm": "^9 || ^10 || ^11"`.

Official packages add:

- `plugin-seo@3.93.0` adds a `./types` export and `./fields`, and sets `"sideEffects": ["*.scss", "*.css"]` so bundlers keep the stylesheets.
- Published peers are **exact**: `"payload": "3.93.0"`, `react`/`react-dom` `^19.0.1 || ^19.1.2 || ^19.2.1`.
- `@payloadcms/ui` and `@payloadcms/translations` are pinned dependencies (`3.93.0`). `plugin-multi-tenant` makes `@payloadcms/ui` a peer instead.
- Official plugins can pin exactly because they ship in lockstep with Payload. A community plugin cannot.

Community conventions observed (npm, fetched 2026-11-06):

| Plugin | Peers | Exports | Build |
|---|---|---|---|
| payload-totp 3.0.7 | `payload`, `@payloadcms/ui`, `@payloadcms/next`, `@payloadcms/translations` all `^3.88.0` | `.`, `./client`, `./rsc` | template build (swc + tsc), `prepublishOnly: clean && build` |
| payload-passkey 2.1.7 | `payload`/`@payloadcms/ui`/`@payloadcms/translations` `>=3.69.0 <4`, `next ^16`, `react >=19` | per-component subpaths | `tsdown --minify`, `sideEffects: ['**/*.css', '**/*.styles.js']` |
| payload-auth 3.0.0 | `payload`/`ui`/`next` `>=3.79.1 <4`, `next >=15.4.8 <17`, `react >=19.2.1 <20` | `payload-auth/better-auth` and others | monorepo |
| @delmaredigital/payload-better-auth 0.14.1 | `>=3.90.0 <4` | | |
| payload-oauth2 1.0.21 | `^3` | none (main only) | `tsc` |

Recommended peer convention: `"payload": ">=3.X.0 <4"` and the same range for `@payloadcms/ui` (and `@payloadcms/next` if its templates are imported), where X is the lowest version tested. `^3.X.0` is equivalent. Add `react`/`react-dom` `^19` and `next` `^15 || ^16` only if the plugin imports them directly.

**Version matching.** The troubleshooting doc says: "All `payload` and `@payloadcms/*` packages must be on exactly the same version and installed only once". Mismatches cause, for example, `TypeError: Cannot destructure property 'config' of...` from a broken React context (`useConfig` from version A, provider from version B). The fix is to pin `payload`, `@payloadcms/*`, `react` and `react-dom` exactly, then reinstall.

For a plugin this means **`@payloadcms/ui` must be a peer, never a regular dependency**; otherwise a second copy gets installed. The plugin must also not bundle React.

**Minor-release breakage.** The [versioning policy](https://github.com/payloadcms/payload/blob/main/docs/migration-guide/versioning.mdx) (v4 docs, fetched 2026-11-06) lets minor releases change the following:

- "Internals. `payload/internal`, anything marked `@internal`, undocumented exports, imports from `dist/`, and undocumented subpaths like `@payloadcms/ui/utilities/*`"
- `@experimental` APIs (`definePlugin`)
- "Admin UI markup. DOM structure, class names and layout", with documented CSS variables covered
- wording and translation strings
- security fixes: "If we can't fix a vulnerability without changing behavior, the fix ships anyway"

The 3.90.0 JWT `authVersion` change is an example of the security exception breaking token-minting plugins in a minor release. Pin CI to the latest Payload minor and test each new release.

### 7.4 Custom endpoints

Endpoint type (REST doc): `{ path, method: 'get'|'head'|'post'|'put'|'delete'|'connect'|'options', handler(req: PayloadRequest) => Promise<Response> | Response, custom? }`. The template types handlers as `PayloadHandler`.

**Where to add them:**

- `config.endpoints` (root): mounted under `routes.api`, for example `/api/my-plugin-endpoint`. payload-totp's `/api/verify-totp` lives here.
- `collection.endpoints`: mounted under `/api/<slug>/<path>`, for example `/api/users/passkey/verify`. payload-oauth2's `/api/users/oauth/…` lives here.
- Paths support params (`'/:id/tracking'` → `req.routeParams.id`).

**What `req` carries:**

- `req.payload`, the Local API. Calls respect access control unless `overrideAccess` is set; in Payload 4 Local API calls **default to `overrideAccess: false`**.
- `req.user`, already resolved by the auth strategies. The handler must enforce it: "Custom endpoints are not authenticated by default".
- `req.headers` and `req.routeParams`.
- `await req.json()`. The body is not parsed automatically. `await addDataAndFileToRequest(req)` (from `payload`) fills `req.data` and `req.file`, and `addLocalesToRequestFromData(req)` fills `req.locale`.

**Responses:** return a web `Response`, for example `Response.json(body, { status, headers })`. Set cookies with `headers.append('Set-Cookie', generatePayloadCookie(...))`. CORS is not applied to custom endpoints automatically: wrap with `headersWithCors({ headers: new Headers(), req })`.

**Routes outside `/api`** need a Next route handler in the host app. A plugin cannot add those; it can only document them.

**Testing a handler directly**, as in the template `dev/int.spec.ts`:

```ts
const payloadRequest = await createPayloadRequest({ config, request: new Request(url) })
const res = await handler(payloadRequest)
```

### 7.5 Dev app and testing (template layout)

```
templates/plugin/
  .swcrc  eslint.config.js  package.json  playwright.config.js  tsconfig.json  vitest.config.js
  src/index.ts  src/exports/{client,rsc}.ts  src/components/*  src/endpoints/*
  dev/payload.config.ts  dev/seed.ts  dev/int.spec.ts  dev/e2e.spec.ts  dev/helpers/{credentials,testEmailAdapter}.ts
  dev/next.config.mjs  dev/tsconfig.json  dev/.env.example
  dev/app/(payload)/admin/[[...segments]]/{page,not-found}.tsx  dev/app/(payload)/admin/importMap.js
  dev/app/(payload)/api/[...slug]/route.ts  dev/app/(payload)/layout.tsx  dev/app/my-route/route.ts
```

**The dev app** is a complete Payload and Next app in `dev/`:

- **Config:** `dev/payload.config.ts` uses `mongooseAdapter` with `process.env.DATABASE_URL` (`.env.example`: `mongodb://127.0.0.1/payload-plugin-template`, `PAYLOAD_SECRET`). When `NODE_ENV === 'test'` it starts `mongodb-memory-server` (`MongoMemoryReplSet`, 3 nodes) instead. The template ships `@payloadcms/db-postgres` and `@payloadcms/db-sqlite` as devDependencies, but the config uses Mongo.
- **Import map:** `admin.importMap.baseDir` is set to `dev/`.
- **Resolving the plugin:** `dev/tsconfig.json` maps `plugin-package-name-placeholder` (and `/client`, `/rsc`) to `../src/*`, and `next.config.mjs` adds a webpack `extensionAlias` so `.js` imports resolve `.ts`. The dev app therefore imports the plugin exactly as a user would.
- **Run:** `pnpm dev` = `next dev dev --turbo`, run from the repo root (payload-totp uses `payload run ./dev/server.ts`).
- **Payload CLI:** goes through `dev:payload` = `cross-env PAYLOAD_CONFIG_PATH=./dev/payload.config.ts payload`, giving `dev:generate-importmap` and `dev:generate-types`.

**Integration tests:** `vitest` (`vitest.config.js` loads `dev/.env` through `loadEnv` from `payload/node`, uses `vite-tsconfig-paths`, and sets 30 s hook and test timeouts). They call `getPayload({ config })` in `beforeAll`, `payload.destroy()` in `afterAll`, and `createPayloadRequest` to call handlers directly.

**End-to-end tests:** Playwright (`testDir: './dev'`, `testMatch: '**/e2e.spec.{ts,js}'`, chromium, `webServer: { command: 'pnpm dev', reuseExistingServer: true, url: 'http://localhost:3000/admin' }`). The sample logs in through `#field-email`, `#field-password` and `.form-submit button`. Those selectors are "Admin UI markup" and may change between minors.

**For WebAuthn e2e**, Playwright's CDP virtual authenticator works on chromium (`WebAuthn.addVirtualAuthenticator`). That comes from general knowledge, not from a Payload source: **verify**.

**CI:** the docs recommend running the tests in a GitHub workflow, tagging the repo with the `payload-plugin` topic for discovery, and using semver where "all major versions reference their Payload compatibility".

### 7.6 Admin views, the login view and providers for an auth plugin

**New admin view:**

```ts
admin.components.views.passkeys = {
  Component: { path: 'my-plugin/rsc#PasskeysView', serverProps: {...} },
  path: '/passkeys',
  exact: true,
}
```

- **Props:** the view receives `AdminViewServerProps` (`initPageResult` with `req`, `payload`, `permissions`, `locale`, `visibleEntities`; `params`, `searchParams`, `i18n`, read-filtered `user`).
- **Template:** wrap it in `DefaultTemplate` (from `@payloadcms/next/templates` in v3; `@payloadcms/ui/rsc` in v4) for the nav. payload-totp's verify and setup screens use the minimal look.
- **Security:** it is **public by default**, so check `initPageResult.req.user`.
- **Path-matching gotcha:** payload-totp registers each view twice with the same path but different keys (`SetupTOTP` and `SetupTOTPBackslash`). It also spreads the host's `views` *after* its own to fix [issue #46](https://github.com/GeorgeHulpoi/payload-totp/issues/46).

**Overriding `/admin/login`.** Choose one of these, from least to most invasive:

1. `admin.components.beforeLogin` / `afterLogin`, to add a passkey button next to the stock form (payload-passkey).
2. `admin.components.views.login`, which replaces the view and works in source since PR #14066 (2025-10-10) but is **undocumented**.
3. `admin.routes.login` set to a different path plus your own view and a redirect (payload-auth).

Option 2 or 3 is needed to add a PIN step *before* the password form, or to make passkeys the default. Option 1 is enough for "or sign in with a passkey". Any second-factor step after the password, such as a PIN, needs a separate view plus a strategy or access gate (the payload-totp pattern), because the stock login form cannot be intercepted ([Discussion #2555](https://github.com/payloadcms/payload/discussions/2555)).

**`admin.components.providers`** is the place for client context: a WebAuthn client, a session-refresh watcher, or a "needs second factor" redirect. payload-totp's provider uses an RSC wrapper (`payload-totp/rsc#TOTPProvider` with server props) around a `'use client'` provider.

**Logout.** `admin.components.logout.Button` replaces the button. An `afterLogout` collection hook can clear plugin cookies, as payload-totp's `deleteCookieAfterLogout` does.

**Payload 4 forward compatibility.** Import router hooks and `Link` from `@payloadcms/ui` (`useRouter`, `usePathname`, `useSearchParams`, `PayloadLink`), not from `next/*`. Read view templates from `@payloadcms/ui/rsc`. Use documented CSS variables, not `--theme-*`. All of this comes from the [v4 migration guide](https://github.com/payloadcms/payload/blob/main/docs/migration-guide/v4.mdx), fetched 2026-11-06. Payload 4 is in beta (`4.0.0-beta.7`, 2026-11-04) with no published release date: **uncertain**.

### 7.7 Implications for a passkey and PIN plugin (synthesis)

These are design suggestions drawn from the evidence above, not established practice.

- **Mint native sessions.** After verifying a WebAuthn assertion or a PIN in an endpoint, repeat Payload's login steps: `getFieldsToSign` → `addSessionToUser` (`payload/shared`) → collection `beforeLogin` hooks → `jwtSign` (`payload`) → `afterLogin` hooks → `generatePayloadCookie`, set with `Set-Cookie`.
- **Why native:** the existing `local-jwt` strategy, logout (`allSessions`), password-change revocation, `autoRefresh` and `/me` then all keep working, and no extra strategy is needed. The local strategy must stay enabled (no `disableLocalStrategy`). This avoids the [UPDOT #160](https://github.com/UPDOT/payload-auth-plugin/issues/160) and payload-oauth2 pitfall of hand-signed tokens without `authVersion`.
- **Mind the internal APIs.** These helpers are semi-internal exports; cover them with an integration test that runs against each new Payload minor.
- **Store credentials in their own collection** (credential ID, public key, counter, transports, user relationship), hidden from the admin and not readable through the API. One reason: login and refresh write back the whole user document they read (the payload-totp README), which can race counters stored on the user. Keep challenges short-lived and single-use. Payload's Local API has no atomic consume (the delmare README), so use a unique index plus delete-on-use, or the HttpOnly challenge-cookie pattern.
- **Require an authenticated, recent session to register a passkey** (payload-passkey's "fresh session" step-up), and check `Origin` against the RP origin.
- **Count PIN attempts outside the user document**, as payload-totp does, and reuse `maxLoginAttempts` and `lockTime`.
- **Keep the plain-function plugin shape** with a `disabled` option that keeps the schema. Take options for the users collection (default `config.admin.user`) and the RP ID and origin. Ship `.`, `./client` and `./rsc` exports, with `@payloadcms/ui` as a peer. Document `payload generate:importmap`.

---

## 8. Security pitfalls when bolting auth onto a framework

### 8.1 CSRF on custom endpoints

- Payload's own CSRF protection is an **Origin allowlist applied when it reads the auth cookie**. In `payload@3.90.2` (`node_modules/payload/dist/auth/extractJWT.js`, read 2026-11-06): if the request has an `Origin` header, the cookie token is used only when `config.csrf` is empty or contains that origin; with no `Origin` and a non-empty `csrf` list it falls back to `Sec-Fetch-Site`, accepting `same-origin`, `same-site` and `none` and rejecting `cross-site` or a missing header. `serverURL` is added to `csrf` automatically (https://payloadcms.com/docs/authentication/cookies, 3.x). This protects any plugin endpoint that authenticates through `req.user`/`payload.auth()`, but **only for cookie auth**; it says nothing about an endpoint that reads a plugin-issued cookie of its own.
- OWASP CSRF cheat sheet (fetched 2026-11-06, https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html): use the framework's protection; never change state on GET; for stateless apps the signed double-submit cookie (HMAC-SHA-256 of a session-bound value + random, compared in constant time, token read from a header or body, never the cookie alone); verify `Origin` (fall back to `Referer`), matching the full origin, and reject state-changing requests with neither header unless another defence passes; `Sec-Fetch-Site` as a layer (block `cross-site` on unsafe methods; legacy browsers lack it); custom request headers on JSON APIs work because they force a CORS preflight, but only if CORS is tight; `SameSite` is defence in depth (Lax still allows top-level GET navigations, scope is the registrable domain so sibling subdomains are "same-site", some clients ignore it); `__Host-` prefix stops subdomain cookie overwrite; XSS defeats every CSRF defence.
- **Login CSRF** applies to the passkey sign-in endpoint: an attacker could complete a WebAuthn ceremony in their own browser and then POST the assertion into a victim's browser so the victim is signed in as the attacker. Because the challenge is bound to the issuing browser (a pre-session cookie or a server record keyed to that cookie), and the response is checked against *that* challenge, the attack fails; this is a reason to bind challenges to the requesting session and not merely to a user ID. Also rotate the session on sign-in.
- For the plugin's endpoints: accept only `application/json` with a non-simple content type (preflight), check `Origin` against `serverURL` + `csrf` list, require the WebAuthn response to match a challenge stored for *this* browser, and make every state change a POST. WebAuthn itself is CSRF-resistant for the ceremony (origin is signed into `clientDataJSON`), but the surrounding "set PIN", "remove passkey", "lock", "unlock with PIN" endpoints are not.

### 8.2 Cookie flags

- Payload's cookie is `${cookiePrefix}-token` (default `payload-token`), `HttpOnly`, `Secure` when `auth.cookies.secure` is true or `sameSite === 'None'`, `SameSite` from `auth.cookies.sameSite` (`true` → `Strict`), optional `domain` (`cookies.js`, read 2026-11-06). `Secure` cannot be on at `http://localhost`, so hosts set it per environment (Payload docs).
- OWASP Session Management cheat sheet (fetched 2026-11-06): `Secure` mandatory, `HttpOnly`, `SameSite=Strict` (or `Lax`), `__Host-` prefix for session cookies (requires `Secure`, `Path=/`, no `Domain`), leave `Domain` unset, narrow `Path`, don't rely on browser close to end sessions, ≥64 bits of entropy (128 preferred) for any session ID the plugin mints, invalidate server-side on logout and send `Clear-Site-Data`.
- A plugin-issued cookie (challenge cookie, "unlocked until" cookie, device-trust cookie) should be `__Host-`-prefixed, `HttpOnly`, `Secure` (outside localhost), `SameSite=Strict`, short `Max-Age`, and HMAC-signed with `PAYLOAD_SECRET`-derived key material (never the raw secret, which also signs Payload's JWT; derive with HKDF or `crypto.createHmac('sha256', secret).update('plugin:purpose')`).

### 8.3 Rate limiting without a shared store on serverless

- **Payload 3 has no IP rate limiter** (`rateLimit` is absent from `node_modules/payload/dist/config/types.d.ts` in 3.90.2; the "Preventing abuse" docs page no longer documents it; GitHub issue #10321, Jan 2025, notes the old docs were stale). What it has is per-account **`maxLoginAttempts` + `lockTime`** (ms) on auth collections, implemented as a counter and lock timestamp on the user document (`incrementLoginAttempts`), and it is only applied by the local (password) strategy. A passkey/PIN plugin must bring its own.
- In-memory counters do not work across serverless instances. Options: (a) **per-account counters in the database** via the Payload Local API (`loginAttempts`, `lockUntil` style fields on the user or on a `passkey-attempts` collection, incremented with an atomic update where the adapter allows, otherwise with optimistic re-read). This is the OWASP-recommended axis anyway: "count failures against the account, not the source IP, so attackers can't evade it by rotating addresses" (Authentication cheat sheet, fetched 2026-11-06), with exponential back-off capped after 2–3 steps and a lockout DoS mitigation (locked users can still use e-mail reset). (b) **Vercel WAF rate limiting** via `@vercel/firewall` `checkRateLimit('rule-id', { request, rateLimitKey })` returning `{ rateLimited }`; counters are per region ("traffic matching a given rate limit key in multiple regions can exceed the limit"), available on Hobby (3 rules) and Pro (usage-billed), and needs a rule created in the dashboard (https://vercel.com/docs/vercel-firewall/vercel-waf/rate-limiting-sdk, last updated 2026-07-23). Vercel-only, so it belongs in the host app, not the plugin. (c) **`@upstash/ratelimit`** over Upstash Redis HTTP (MIT; sliding window etc.) for hosts that already have Redis (https://github.com/upstash/ratelimit-js). Design the plugin with a `rateLimiter` hook so hosts can plug in (b) or (c), and ship (a) as the default because it works on every DB adapter.
- WebAuthn assertions can't be brute-forced (the challenge is random and signatures are verified), so rate limiting matters mainly for: PIN attempts (critical), challenge issuance (resource exhaustion), and username→"has passkeys" probes (enumeration).

### 8.4 Timing attacks

- Compare HMACs, recovery codes and PIN hashes with `crypto.timingSafeEqual`, which requires equal-length inputs and throws `RangeError` (`ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH`) otherwise; an early `length !== length` return leaks the length. Standard pattern: HMAC both sides with a server key (fixed length) and compare the digests (Node docs; Simon Willison's TIL and Cloudflare's example, fetched 2026-11-06).
- For PIN verification the whole path should take the same time whether the user exists, is locked, or the PIN is wrong: always run the KDF (or an equivalent dummy) before deciding (OWASP Authentication: "run the same processing path regardless of whether the user exists"). argon2id/scrypt verification time dwarfs any comparison timing, but the "user not found → return early" branch is the classic leak.

### 8.5 User enumeration

- Spec §14.6.2 (fetched 2026-11-06): a sign-in endpoint that fails for unknown e-mails but succeeds for known ones leaks who has an account. Mitigations: for authentication, prefer **usernameless/discoverable flow** (empty `allowCredentials`, user resolved from `userHandle`), so the RP never has to answer "does this e-mail have passkeys"; if an identifier-first flow is needed, return a plausible, deterministic fake `allowCredentials` list for unknown users (the spec's suggestion) and the same HTTP status and timing. Spec §13.4.7 "Unprotected account detection" covers the same for non-empty `allowCredentials`.
- OWASP: one generic message ("Login failed; invalid user ID or password") and identical status codes for wrong user, wrong credential, locked, and disabled; same for recovery-code and PIN endpoints.
- Signal API: call `signalAllAcceptedCredentials` only when signed in (it reveals the count of passkeys); `signalUnknownCredential` is safe signed-out (Chrome docs, 2024-11).

### 8.6 Audit logging

- OWASP Logging cheat sheet (fetched 2026-11-06): always log authentication successes and failures, authorisation failures, session anomalies, user administration (add/remove credential, privilege change, token changes) and all admin actions; each event with when/where/who/what (timestamp, app, URL + method, source IP and user, event type, severity, outcome). Never log passwords, tokens, session IDs (hash them if needed), keys or secrets. Use a structured format (JSON), strip CR/LF to prevent log injection, protect integrity.
- For the plugin: an `auth-events` collection (or `payload.logger` lines) for passkey registered/removed/renamed, sign-in success/failure (with credential ID and AAGUID, never the signature or challenge), PIN set/changed, PIN failures and lockouts, lock/unlock, step-up success/failure, recovery-code use; plus a `lastUsedAt` on each credential for the management UI.

### 8.7 Secrets

- `PAYLOAD_SECRET` signs the JWT; Payload hashes it (SHA-256, first 32 chars) before use. A plugin must not reuse it raw for a different purpose; derive a per-purpose key (HKDF/HMAC with a label) so a weakness in one scheme doesn't expose another. Any pepper for PIN hashing should be its own env var (or derived) and rotation planned (store a key id with each hash).
- Keys and server-only modules: the plugin's server code must import `server-only`-style guards or at least never be reachable from client bundles; Payload's import-map convention (`'plugin/client#X'` vs `'plugin/rsc#X'`) exists precisely to keep server code out of the browser bundle (see section 7).
- Don't trust `x-forwarded-for` blindly for rate-limit keys or audit IPs unless the host says the proxy is trusted; on Vercel `x-real-ip`/`x-forwarded-for` are set by the platform.

### 8.8 Don't rely on Next.js middleware alone

- CVE-2025-29927 (public 21 Mar 2025; patched in 15.2.3, 14.2.25, 13.5.9, 12.3.5): a spoofed internal `x-middleware-subrequest` header skipped middleware entirely on self-hosted `next start`/standalone deployments; Vercel/Netlify/Cloudflare were not affected because routing runs outside the app. Vercel's postmortem: "We do not recommend Middleware to be the sole method of protecting routes in your application" (https://vercel.com/blog/postmortem-on-next-js-middleware-bypass, 2025-03-25). For the plugin: enforce lock/step-up state **in Payload** (access functions, hooks, a custom auth strategy that refuses to return a user when the session is locked), not in a Next.js proxy/middleware, and treat any client-side overlay as presentation only. Payload's own custom admin views are not auth-protected automatically (this repo's generator view checks `req.user` itself, per CLAUDE.md), so every plugin view and endpoint must check the user and the lock state.

### 8.9 WebAuthn-specific gotchas

- Verify `clientDataJSON.type` (`webauthn.create`/`webauthn.get`), `origin` against the full expected origin list, `rpIdHash` against SHA-256 of the configured RP ID, and reject `crossOrigin: true` unless you deliberately support iframes (L3 adds `topOrigin`). Reject registration if the credential ID is already known (any user). Enforce `alg` in the allowed list. Keep `userHandle` opaque (64 random bytes) and never derive it from e-mail.
- Credential IDs are not signed by the authenticator (spec §13.4.6 L2 / "Credential ID unsigned"); look up by credential ID and verify the signature with the stored key, never trust the ID alone.
- The AAGUID list retirement (section 1.12) is an operational pitfall: a plugin that fetches the community JSON at runtime will start showing nothing in January 2027.

---

## 9. Recommendations for the plugin

These are opinions drawn from the evidence above. Where a recommendation rests on an undocumented Payload export or a behaviour inferred from source, it is marked **(fragile)**.

### 9.1 Which product shapes to support in v1

| Shape | v1? | Reasoning |
|---|---|---|
| (a) Passkey sign-in **alongside** email + password | **Yes, the core.** | Lowest risk, matches Craft 5 / Statamic 6 and passkeys.dev guidance ("offer after a strong sign-in"). Keep Payload's local strategy on; never set `disableLocalStrategy` (3.90+ `local-jwt` rejects tokens for such collections, and password reset is the recovery path). Add a "Sign in with a passkey" button via `admin.components.afterLogin`, plus conditional UI on the e-mail field. |
| (a′) Passwordless (passkey replaces password) | No, v2 as a per-role policy `passwordLogin: 'allowed' \| 'disallowed'` | Needs recovery codes, admin reset and an e-mail fallback before it is safe. Statamic's `allow_password_login_with_passkey` is the model. |
| (b) Passkey as a **second factor** after the password | **Yes, as an enforcement option by role** (`requireSecondFactor: ['admin']`) | The passkey-after-password gate is the payload-totp pattern: a `beforeLogin`/`afterLogin` hook marks the new session "pending second factor" in the plugin's session record, every access function refuses while pending, and a second-step view completes it. Gate *every* login path (REST, GraphQL, `refresh-token`, `reset-password`, API keys), not just the UI; WordPress Two Factor's REST bypass and Statamic's elevated-session bypass are the cautionary tales. TOTP itself is out of scope (payload-totp exists); a passkey with UV *is* two factors. |
| (c) Idle **lock screen** unlocked by passkey (or PIN) | **Yes**, passkey unlock in v1; PIN unlock as an opt-in | This is the "fingerprint / passcode" feature the developer asked for. Lock in place (modal over the current view, like Craft's AuthManager and WordPress's `wp_auth_check`) so autosaved drafts survive. Server-enforced: see 9.4. |
| (d) **Step-up** before sensitive actions | **Yes, minimal**: required for passkey enrol/remove, PIN set/change, recovery codes, changing another user's factors, API-key creation; configurable `sensitiveOperations` for host collections in v2 | GitHub sudo (2 h), Craft (5 min), Statamic (15 min). Use 5 minutes by default. Represent it as `authTime`/`amr`/`stepUpUntil` on the server-side session record and answer with a `step_up_required` JSON error the admin UI turns into a passkey prompt (RFC 9470 shape). A PIN unlock must **not** satisfy step-up. |

### 9.2 Library

**`@simplewebauthn/server` + `@simplewebauthn/browser` v14** (`^14.0.3` / `^14.0.0`, MIT, ~9.7 M weekly downloads, security releases in Sept 2026; see section 2). Pin `^13.3.3` only if Node 20 hosts must be supported (Payload 3.91 still allows Node 20.18.1 while SimpleWebAuthn 14's changelog says Node 22). Reasons: the only maintained full-ceremony RP library in TypeScript; array `expectedOrigin`/`expectedRPID`; `credentialDeviceType`, `credentialBackedUp`, `aaguid` for the UI; `sendSignal()`; WebCrypto-based so no Node shims. Import it only from server files (endpoints, hooks) and never from any path reachable by `payload.config.ts` client components; the client-import test pattern this repo already uses for the generator should be copied into the plugin's test suite.

Do not build on Better Auth or Auth.js: both bring their own session model that fights Payload's. `payload-passkey` (Aug 2026) shows the cost: it requires the whole Better Auth library.

### 9.3 Storage model (works on Mongo, Postgres and SQLite through the Local API)

- **`passkeys` collection** (slug configurable; `admin.hidden`, `access.read` only the owning user, `create/update/delete: () => false` through the API, every write through the plugin's endpoints with `overrideAccess: true`): `user` (relationship, indexed), `credentialId` (text, unique index, base64url), `publicKey` (text, base64url COSE), `counter` (number), `transports` (json), `deviceType` (`singleDevice`/`multiDevice`), `backedUp` (checkbox), `aaguid` (text), `name` (text, user-editable, defaulted from AAGUID lookup at display time), `createdAt`, `lastUsedAt`. Separate collection, not fields on the user: login/refresh write back the whole user document and would race the counter and `lastUsedAt` (payload-totp README).
- **`webauthn-challenges` collection**: `challenge` (unique), `type` (`registration`/`authentication`/`unlock`/`stepUp`), `user` (optional), `browserKey` (a random value set in an `HttpOnly` `__Host-` cookie at issuance, so the response must come from the same browser: this also defeats login CSRF), `expiresAt` (TTL ≤ 5 min; Mongo TTL index where available, otherwise delete-on-read and a sweep in a `beforeOperation`). Consume by `delete` on first use, success or failure. Store 32-byte challenges (spec minimum 16).
- **Session state** keyed by Payload's `sid` (`req.user._sid`, present when `useSessions` is on): a `passkey-sessions` collection `{ sid (unique), user, authTime, amr: ['pwd'|'webauthn'|'pin'], secondFactorPending, lockedAt, lastActivityAt, stepUpUntil }`. Created in `afterLogin`, deleted in `afterLogout`, pruned when the Payload session expires. Payload's own `sessions` array cannot be extended by a plugin (`update: () => false`, base field) **(inferred from source)**.
- **PIN** (opt-in): on the user document or a `passkey-pins` collection: `pinHash` with a versioned prefix (`scrypt-v1:` …), `pinAttempts`, `pinLockedAt`. Hash = `scrypt(HMAC-SHA256(pepper, pin), salt, N=2^15, r=8, p=3)` with `pepper` derived from `PAYLOAD_SECRET` by HMAC with a plugin label (or an explicit `PASSKEY_PIN_PEPPER`), compared with `timingSafeEqual`. Default 6 digits, floor 4, blocklist trivial PINs, 5 attempts then the PIN is dropped and a full login is required (no timed lockout to wait out). Increment attempts atomically with `payload.db.updateOne({ data: { pinAttempts: { $inc: 1 } } })`, which is what Payload's own `incrementLoginAttempts` uses across adapters **(fragile: internal pattern)**.
- **Audit**: `auth-events` collection (or structured `payload.logger` lines) per section 8.6; never store signatures, challenges, or PINs.

### 9.4 Session minting, lock and step-up enforcement

- **Mint native Payload sessions**: after a verified assertion, run Payload's own login steps (`getFieldsToSign` → `addSessionToUser` from `payload/shared` → `beforeLogin` hooks → `jwtSign` with the current `authVersion` → `afterLogin` hooks → `generatePayloadCookie`) rather than a custom auth strategy or a hand-signed JWT. That keeps logout, `allSessions`, password-change revocation, `autoRefresh` and `/me` working, and avoids the 3.90.0 `authVersion` break that hit `payload-auth-plugin`. These helpers are exported but undocumented **(fragile)**: cover them with an integration test per Payload minor and pin `payload` as a peer with a tested range.
- **Lock enforcement must be server-side.** Custom strategies cannot veto `local-jwt`, so wrap `access.read/create/update/delete` of every collection and global (and `admin` access) with a check that loads the session record for `req.user._sid` once per request (`req.context` cache) and returns `false` while `lockedAt` is set or `secondFactorPending` is true. Exempt the plugin's own unlock endpoints, the logout operation, and requests with no `req.user` (server code). The admin provider (`admin.components.providers`) watches `lastActivityAt`/idle time, calls `POST /api/passkey/lock` on idle (and on tab hide if configured), and shows the modal; the server also auto-locks when `now - lastActivityAt > idleMs` on the next request, so a client that never fired the timer is still locked. Unlock = a WebAuthn `get()` with `userVerification: 'required'` and `allowCredentials` limited to the signed-in user's passkeys (or the PIN), which clears `lockedAt`. Note the lock does not end the Payload session; `tokenExpiration` still governs that.
- **Step-up**: `requireFresh(req, { maxAgeSec: 300, methods: ['webauthn'] })` in `beforeChange`/`beforeDelete` hooks (so a JSON error body can carry `{ stepUp: { maxAge, methods } }`), applied to the plugin's own collections and, via a `sensitiveOperations` option, to host collections/fields (`roles`, `email`, `password`, `enableAPIKey`). Rotate the Payload session (new `sid`) after step-up that raises privilege.
- Register the plugin's endpoints under `config.endpoints` with a single prefix (`/api/passkey/*`), POST only, `application/json` only, `Origin` checked against `serverURL` + `csrf`, user checked in every handler, per-account rate limit, and a `rateLimiter` option so hosts can plug in Vercel WAF or Upstash.

### 9.5 WebAuthn options to use

`residentKey: 'required'`, `userVerification: 'required'` and `requireUserVerification: true` on verify (admins can set up a PIN/biometric; a UV-less passkey must not unlock a CMS), `attestation: 'none'`, `pubKeyCredParams` ES256/RS256/EdDSA, `excludeCredentials` = the user's existing passkeys, `extensions: { credProps: true }`, `user.id` = 64 random bytes stored on the user (never e-mail), `timeout` 300 000 ms, challenge 32 bytes. Store BE/BS; log and flag (don't fail) a non-increasing counter unless the credential is device-bound (BE=0). Call `signalAllAcceptedCredentials` after delete/rename and on sign-in (only when signed in), `signalUnknownCredential` when an assertion names an unknown credential, `signalCurrentUserDetails` when e-mail/name changes. Feature-detect everything through `getClientCapabilities()` with `isConditionalMediationAvailable` as fallback. Skip conditional create in v1.

### 9.6 RP ID and origin handling

- Options: `rpID?: string`, `origins?: string[]`, `allowedHosts?: string[]`. Defaults: RP ID = hostname of `config.serverURL`; origins = `[serverURL]`. In development, if `serverURL` is `http://localhost:*`, RP ID `localhost` works (loopback is a secure context).
- **Vercel previews**: `vercel.app` is on the Public Suffix List, so every `*.vercel.app` host is its own RP ID and a passkey made on one preview is useless on the next. Default behaviour: when the request host does not match the configured RP ID (or a subdomain of it), the plugin renders the stock login only and shows an admin notice "Passkeys are available on <rpID> only". Document two ways to get passkeys on previews: a stable custom preview domain under the production domain (`preview.example.com` with RP ID `example.com`, which Vercel supports through custom environment domains / Preview Deployment Suffix on Pro), or accepting password login on previews. Related Origin Requests do not help here (5-label cap, and all previews share a public suffix).
- Verify `clientDataJSON.origin` against the full origin list and `rpIdHash` against the configured RP ID independently; accept arrays so one deployment can serve `example.com` and `www.example.com`.
- Changing `rpID` later breaks every passkey unless the new value is a parent domain; say so in the README and store the RP ID on each credential so the UI can show "made for cms.example.com" and offer re-enrolment.

### 9.7 Recovery and lost devices

1. Keep the password: v1 never disables Payload's local strategy, so `forgot-password` remains the recovery path, and enforcement mode (b) can be satisfied by a passkey on any device including cross-device/QR from a phone.
2. Encourage a second passkey (synced passkeys already survive device loss; prompt after a cross-device sign-in to add a local one; show a warning when the only passkey is device-bound, BE=0).
3. Admin reset: a step-up-protected action on another user's document that removes their passkeys/PIN and ends their sessions (WordPress Two Factor profile tick-boxes, Craft CLI).
4. Single-admin escape hatch: a `payload run` / `bin` script `passkey:reset --email` using the Local API with `context: { disableRevalidate: true }`, and an env var `PASSKEY_ENFORCEMENT_BYPASS_EMAIL` that lifts the second-factor requirement for **one named account** (never a global off switch), logged loudly.
5. Recovery codes (hashed, shown once, downloadable, low-remaining warning) only arrive with the passwordless mode in v2.
6. Confirm before deleting the last passkey, and refuse to delete it when it is the user's only second factor in enforcement mode.

### 9.8 Plugin packaging

Plain function `passkeyPlugin(options)(config)` spreading the incoming config, with `enabled: false` keeping the schema; `.`, `./client`, `./rsc` exports built ESM-only with swc + tsc; `payload`, `@payloadcms/ui`, `@payloadcms/next`, `react`, `next` as peers (Payload requires exact matching `@payloadcms/*` versions); admin components registered by import path and documented `payload generate:importmap`; a `dev/` Next app with Mongo and SQLite configs plus Vitest int tests (`getPayload` with a real adapter, SimpleWebAuthn's test vectors or a virtual authenticator via Playwright's CDP `WebAuthn.addVirtualAuthenticator`) and one int test that re-runs the native-session minting against each Payload minor. Avoid `definePlugin` until Payload 4 settles. Import router hooks from `@payloadcms/ui` for v4 compatibility. Use `payload.config.custom` or the users collection's `custom` to tell host code which collection holds passkeys.

### 9.9 Open questions to settle with the developer

- Is "passcode" the device passcode (nothing to store: Touch ID / Face ID / Windows Hello already fall back to it) or an app-level PIN? Recommend shipping passkey unlock first and the app PIN as an opt-in for devices without a platform authenticator.
- Idle timeout default (OWASP: 2–5 min high-value, 15–30 min low-risk; suggest 10 min with "Keep me signed in" like Craft) and whether the lock should also fire on tab hide / OS lock.
- Whether enforcement is by role (recommended) or per user, and which roles.
- Whether to support `generatorRunId`-style audit linking of auth events to the admin's activity, or keep audit minimal.

### 9.10 Known uncertainties in this report

- Safari support for the Signal API is contradictory across sources (listed as Safari 26 in badges, "not yet implemented" in text).
- The exact Payload release that moved password hashing from 25 000 to 600 000 PBKDF2 iterations was not pinned (it is before 3.90.2).
- `admin.components.views.login` overriding `/admin/login` is implemented (PR #14066, Oct 2025) but undocumented; `isPublicAdminRoute` using `startsWith` is inferred from source.
- `jwtSign`, `getFieldsToSign`, `addSessionToUser` and the `$inc` update pattern are exported/used by Payload but not in the documented API surface.
- Whether `payload-passkey` (Better Auth based) works on MongoDB, and whether `payload-auth-plugin` allows registering a passkey against another user's e-mail, were not confirmed.
- Sanity passkey support and wordpress.org passwordless login were not confirmed.
- The FIDO MDS consumer-passkey ("C-MDS") public download URL and cadence were not found on the migration wiki page (vendor-side instructions only).
