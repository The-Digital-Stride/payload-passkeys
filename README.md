# @the-digital-stride/payload-passkeys

Passkey sign-in for the [Payload CMS](https://payloadcms.com) admin: Touch ID, Face ID, Windows Hello, an Android fingerprint, or the device's own PIN or password.

## What it does

Admins can add passkeys to their account and sign in to the admin with one, alongside email and password. Passkeys are optional for each admin, and the password and forgot-password always keep working. A passkey sign-in creates an ordinary Payload session, so logout, "log out of all sessions", token refresh, `/me` and session revocation behave exactly as they do after a password sign-in. The plugin stores public keys only: a copy of the database can't be used to sign in.

The plugin adds:

- a **Sign in with a passkey** button under the login form;
- a **Passkeys** section on the account page, to add, rename and remove passkeys;
- a dismissible "Sign in faster with a passkey" prompt after a password sign-in;
- three hidden collections (`passkeys`, `passkey-challenges`, `passkey-challenge-uses`) and, on each configured auth collection, a hidden `passkeyUserHandle` field, a `beforeDelete` hook that removes a deleted user's passkeys, and an `afterRefresh` hook that refuses to refresh a session the plugin has signed out;
- a recovery command, `payload passkeys:reset`.

## Requirements

- Payload `>=3.90 <4`, with `@payloadcms/ui` from the same release.
- Next.js 15.4.8 or later, or Next.js 16.
- React 19.
- Node 22.12 or later. Payload 3.92 and later need Node `^22.23.4` or `>=24.22.1` themselves.
- An auth collection with sessions on (`auth.useSessions`, Payload's default) and the local strategy on.
- The admin served over HTTPS, or on `http://localhost` in development. Browsers allow passkeys only in a secure context.

MongoDB, Postgres and SQLite all work.

## Install

```bash
pnpm add @the-digital-stride/payload-passkeys
```

Add `passkeysPlugin()` to `plugins` in your Payload config:

```ts
import { passkeysPlugin } from '@the-digital-stride/payload-passkeys'

export const plugins: Config['plugins'] = [passkeysPlugin()]
```

With `serverURL` set, that is enough: the RP ID and the allowed origin come from it. Without `serverURL`, pass `rpID` and `origins`.

### Options

Every option is optional.

| Option                       | Type                                         | Default                                                          | What it does                                                                                                                                                      |
| ---------------------------- | -------------------------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `clientIp`                   | `(req) => string \| null \| undefined`       | the rightmost `x-forwarded-for` entry                            | Where the caller's IP comes from, for `rateLimit` and failure logs. See [Rate limiting](#rate-limiting).                                                          |
| `collections`                | `string[]`                                   | `[admin.user]`, else the first auth collection                   | Auth collections that get passkeys. Each gets its own endpoints and fields.                                                                                       |
| `enabled`                    | `boolean`                                    | `true`                                                           | `false` keeps the collections, fields, translations and the reset command, but adds no endpoints and no admin components. Turning it off never needs a migration. |
| `enrolmentPrompt`            | `boolean`                                    | `true`                                                           | Offer "Sign in faster with a passkey" after a password sign-in.                                                                                                   |
| `freshSessionMinutes`        | `number` (1 to 60)                           | `10`                                                             | How recent the sign-in must be to add a passkey without re-entering the password.                                                                                 |
| `limits.anonymousChallenges` | `number`                                     | `500`                                                            | Outstanding sign-in challenges across the whole site. Past it, passkey sign-in answers 429 until challenges expire (5 minutes). Password sign-in is unaffected.   |
| `limits.passkeysPerUser`     | `number`                                     | `20`                                                             | Passkeys per account.                                                                                                                                             |
| `logging.ip`                 | `'none' \| 'truncated' \| 'full'`            | `'truncated'`                                                    | IP addresses in failure logs: none, /24 (IPv4) or /48 (IPv6), or in full. Never logged on success.                                                                |
| `onSignIn`                   | `(args) => void \| Promise<void>`            | none                                                             | Runs on every passkey sign-in. See [What a passkey sign-in runs](#what-a-passkey-sign-in-runs).                                                                   |
| `origins`                    | `string[]`                                   | `[serverURL's origin]`                                           | Exact origins (scheme, host, port) the admin is served from. HTTPS, except on localhost. Each must be the RP ID or under it.                                      |
| `rateLimit`                  | `(args) => boolean \| Promise<boolean>`      | allows everything                                                | Called on every request to the plugin's endpoints. See [Rate limiting](#rate-limiting).                                                                           |
| `rpID`                       | `string`                                     | the hostname of the first origin                                 | The WebAuthn relying-party ID: the domain passkeys belong to.                                                                                                     |
| `rpName`                     | `string`                                     | `admin.meta.title`, else the RP ID                               | The name some passkey managers show.                                                                                                                              |
| `slugs`                      | `{ passkeys?, challenges?, challengeUses? }` | `'passkeys'`, `'passkey-challenges'`, `'passkey-challenge-uses'` | Rename the plugin's collections if the names are taken.                                                                                                           |

Every option at its default value, with explicit domains:

```ts
export const configured = passkeysPlugin({
  collections: ['users'],
  enabled: true,
  enrolmentPrompt: true,
  freshSessionMinutes: 10,
  limits: { anonymousChallenges: 500, passkeysPerUser: 20 },
  logging: { ip: 'truncated' },
  origins: ['https://example.com', 'https://www.example.com'],
  rpID: 'example.com',
  rpName: 'Example admin',
  slugs: {
    challengeUses: 'passkey-challenge-uses',
    challenges: 'passkey-challenges',
    passkeys: 'passkeys',
  },
})
```

The plugin checks its options when the config loads and refuses to start, with a message naming the problem, when:

- a listed collection doesn't exist, has no `auth`, sets `disableLocalStrategy`, sets `useSessions: false` or sets `endpoints: false`;
- there is neither `rpID` with `origins` nor a usable `serverURL`;
- the RP ID is a hosting suffix such as `vercel.app`, or an origin isn't the RP ID or under it;
- a collection sets `auth.cookies.sameSite: 'None'` while the `csrf` list is empty;
- a plugin collection's slug is already taken.

The **Sign in with a passkey** button appears on the login page when `admin.user` is one of the configured collections. Other configured collections get the endpoints and the Passkeys section, and need their own sign-in page.

## After installing: generate, and migrate on SQL

Everyone:

```bash
pnpm payload generate:importmap
pnpm payload generate:types
```

Postgres and SQLite: the plugin adds three collections and a field, so create and run a migration:

```bash
pnpm payload migrate:create passkeys
pnpm payload migrate
```

MongoDB needs no migration. Replay protection rests on three unique indexes (`passkey-challenge-uses.challenge`, `passkey-challenges.challenge`, `passkeys.credentialId`), so the plugin builds them itself at boot rather than relying on `ensureIndexes`. The database user needs the `createIndex` privilege. If an index can't be built, the plugin logs an error at boot and turns passkey sign-in and registration off (they answer 503 and the button shows that passkeys aren't available), because without that index a challenge could be used twice. Password sign-in keeps working. Fix the permission or remove the duplicates, and restart.

## Domains, RP ID and preview deployments

The **RP ID** is the domain a passkey belongs to. A browser offers a passkey only on that domain or its subdomains, so a passkey made for `example.com` works on `example.com` and `admin.example.com`, never elsewhere.

- The RP ID defaults to the hostname of `serverURL`, and `origins` to its origin. Set both when the admin is served from more than one address, for example the apex and `www`.
- The RP ID can never be a hosting suffix such as `vercel.app`, `netlify.app` or `pages.dev`: every other site on that suffix could use the passkeys, and browsers refuse it anyway.
- Every origin must be the RP ID or a subdomain of it.
- Changing `rpID` later breaks every existing passkey, unless the new value is a parent domain of the old one. The Passkeys section marks each passkey made for a different RP ID ("Made for …").
- Passkeys made on `localhost` work only there. If local development shares the production database, they appear on the live site as "Made for localhost".

### Preview deployments

Each `*.vercel.app` preview is its own site to a browser, and none of them is under your RP ID. On a preview, the login page shows a short note instead of the button ("Passkey sign-in isn't available at this address"), and password sign-in works as usual. To try passkeys on previews, give them a custom domain under the production domain (for example `preview.example.com`) and add that origin to `origins` and `csrf`.

Every deployment that shares an RP ID must also share one passkeys database. The browser tells the password manager which passkeys the site still knows: after a sign-in with a passkey the server doesn't recognise it calls `signalUnknownCredential`, and the Passkeys section calls `signalAllAcceptedCredentials` with the account's passkeys. A preview under `example.com` with its own database doesn't know the production passkeys, so trying one there can make the password manager delete it; if that database is an older copy of production's, opening the Passkeys section can do the same to every passkey added since. Your admins would then have to sign in with their passwords and register again. Point such previews at the production database, or give them an RP ID of their own.

## CSRF

Payload accepts the session cookie from any site when its `csrf` list is empty, and the list is empty unless `serverURL` or `csrf` is set. If `serverURL` isn't set, set `csrf` to every origin the admin is served from, including preview URLs:

```ts
const serverURL = process.env.NEXT_PUBLIC_SERVER_URL ?? 'http://localhost:3000'

export const csrf: Config['csrf'] = [
  serverURL,
  ...(process.env.VERCEL_URL ? [`https://${process.env.VERCEL_URL}`] : []),
  ...(process.env.VERCEL_BRANCH_URL ? [`https://${process.env.VERCEL_BRANCH_URL}`] : []),
]
```

The plugin warns at boot while the list is empty, and refuses to start when it is empty and a collection sets `auth.cookies.sameSite: 'None'`. Its own endpoints accept only JSON and check the `Origin` header against `origins` regardless, but the rest of the admin depends on `csrf`.

## Rate limiting

Payload has no IP rate limiter, and serverless instances share no memory, so pass a `rateLimit` hook. In production the plugin logs a warning at boot until you do. The hook runs on every request to a plugin endpoint, after the request's checks and before any work, with:

- `action`: `'status'`, `'register.options'`, `'register.verify'`, `'sign-in.options'`, `'sign-in.verify'`, `'reauth'`, `'rename'` or `'delete'`;
- `key`: `<collection>:<userId>` for a signed-in request, `ip:<ip>` for an anonymous one;
- `ip`: the rightmost `x-forwarded-for` entry, or what your `clientIp` option returns; `null` when that isn't an IP address;
- `userId` (signed-in requests only), `collection` and `req`.

Return `true` to allow the request. Anything else refuses it with 429, and so does a throw: the hook fails closed.

The rightmost `x-forwarded-for` entry is the one your nearest proxy appended, so it is the address that proxy saw. Entries to its left, and `x-real-ip`, are whatever the client sent unless a proxy replaced them, so the plugin doesn't read them by default. This is right on Vercel (one entry, set by Vercel) and behind a single nginx or load balancer that appends to `x-forwarded-for`. With no proxy at all a client can send any value, and an IP-keyed limit can be dodged.

With more than one proxy, or a proxy that puts the address in another header, pass `clientIp`. For example `clientIp: (req) => req.headers.get('x-real-ip')` behind nginx with `proxy_set_header X-Real-IP $remote_addr`, or `clientIp: (req) => req.headers.get('cf-connecting-ip')` when Cloudflare is the only way in. A value that isn't an IP address becomes `null`.

**Vercel WAF** with [`@vercel/firewall`](https://vercel.com/docs/vercel-firewall/vercel-waf/rate-limiting-sdk):

```ts
import type { RateLimitHook } from '@the-digital-stride/payload-passkeys'
import { checkRateLimit } from '@vercel/firewall'

export const vercelRateLimit: RateLimitHook = async ({ key, req }) => {
  // The firewall exists only on Vercel; allow everything in local development.
  if (process.env.VERCEL !== '1') return true
  const { error, rateLimited } = await checkRateLimit('passkeys', {
    headers: req.headers,
    rateLimitKey: key,
  })
  // error 'not-found' means no rule has the ID "passkeys": refuse rather than run unlimited.
  return !rateLimited && !error
}
```

Then, in the Vercel dashboard, open the project's **Firewall**, add a custom rule whose condition is the `@vercel/firewall` rate limit ID `passkeys`, and give it a rate-limit action, for example 20 requests per 60 seconds. The `rateLimitKey` decides what each count is per.

**Upstash** with `@upstash/ratelimit`:

```ts
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const limiter = new Ratelimit({
  limiter: Ratelimit.slidingWindow(10, '1 m'),
  prefix: 'passkeys',
  redis: Redis.fromEnv(),
})

export const upstashRateLimit: RateLimitHook = async ({ action, key }) =>
  (await limiter.limit(`${action}:${key}`)).success
```

Pass either as `passkeysPlugin({ rateLimit: vercelRateLimit })`.

Built in, whatever the hook does: at most `limits.passkeysPerUser` passkeys per account, one outstanding sign-in challenge per browser (a new one replaces the old), one outstanding registration per account, a site-wide cap on sign-in challenges (`limits.anonymousChallenges`), and pruning of expired challenges on every new one.

## What a passkey sign-in runs

### Endpoints

Each configured collection gets these endpoints, all `POST` with a JSON body, under `/api/<collection>/passkeys/`:

| Path               | Caller                    | What it does                                                                                                                                                                          |
| ------------------ | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `status`           | anyone                    | `{ available }`: whether passkeys work at the caller's origin. The signed-in owner also gets their passkeys, the RP ID and the reason passkeys are unavailable.                       |
| `register/options` | signed in, recent sign-in | Options for `navigator.credentials.create()`. Answers 403 `reauth_required` when the sign-in is older than `freshSessionMinutes`.                                                     |
| `reauth`           | signed in                 | `{ password }`. A real Payload sign-in for the session's own account, with Payload's attempt counting and lockout. Moves the browser onto the new session and ends the old one.       |
| `register/verify`  | signed in                 | Verifies and stores a new passkey.                                                                                                                                                    |
| `sign-in/options`  | anyone                    | Options for `navigator.credentials.get()`, naming no account.                                                                                                                         |
| `sign-in/verify`   | anyone                    | Verifies the passkey and signs in.                                                                                                                                                    |
| `rename`           | signed in, owner          | `{ id, name }`.                                                                                                                                                                       |
| `delete`           | signed in, owner          | `{ id, signOutOtherSessions? }`. The only way to remove a passkey: REST access to the `passkeys` collection is closed. Answers 503 `retry` when the other sessions couldn't be ended. |

Every endpoint accepts only `Content-Type: application/json` (415 otherwise) and bodies up to 64 KB (413). Every endpoint except `status` requires an `Origin` in `origins`, or no `Origin` and `Sec-Fetch-Site: same-origin` (403). Signed-in endpoints require the browser's session cookie: an API key or a token in an `Authorization` header is refused, so a leaked key can't manage passkeys.

### Order of a passkey sign-in

After the passkey is verified, the plugin repeats what Payload's own login does, without the password:

1. Loads the user. Refuses if the user no longer exists, or is unverified when the collection uses `auth.verify`.
2. Starts a transaction where the adapter supports one.
3. Adds a new session to the user.
4. Resets the failed-login count, when `maxLoginAttempts` is set.
5. Runs the collection's `beforeLogin` hooks, which may change the user or throw to refuse.
6. Runs your `onSignIn`.
7. Signs the token.
8. Runs the collection's `afterLogin` hooks.
9. Builds the response user as `/me` would, with field read access applied and no internal fields, and commits.

A throw anywhere from step 3 ends the new session, rolls back, and fails the sign-in with the generic message. The log line records the reason (`refused_by_hook: <ErrorName>` for a hook).

It does **not** run the collection's `beforeOperation` or `afterOperation` hooks for `login`: Payload doesn't export what would run them. Use `onSignIn` for audit or access rules you keep there:

```ts
export const withAudit = passkeysPlugin({
  // Runs inside the sign-in transaction, after the beforeLogin hooks. Throw to refuse.
  onSignIn: ({ collection, passkey, req, user }) => {
    req.payload.logger.info({
      collection,
      credentialIdPrefix: passkey?.credentialId.slice(0, 8),
      event: 'audit.admin_signed_in',
      method: 'passkey',
      msg: 'audit.admin_signed_in',
      userId: user.id,
    })
  },
})
```

`user` is a copy of the stored user document after the `beforeLogin` hooks, without Payload's internal fields (`hash`, `salt`, `sessions`, `apiKey`, `apiKeyIndex`, the reset and verification tokens, `loginAttempts`, `lockUntil` and `passkeyUserHandle`); changing it changes nothing. `passkey` carries the passkey's public details only. To write to a collection from `onSignIn`, pass `req` so the write joins the sign-in transaction.

**A password lockout doesn't block a passkey.** After too many wrong passwords Payload locks the account (`lockUntil`). A passkey can't be guessed, and honouring the lock would let anyone who knows an admin's email keep them out indefinitely. So a passkey sign-in goes ahead, logs `passkeys.signed_in_while_locked`, and clears the failed-attempt count and the lock, as a successful password sign-in would.

## Recovery

An admin who loses every passkey still has the password and forgot-password. For a site owner locked out entirely, run this in the host project:

```bash
pnpm payload passkeys:reset --collection users --email you@example.com
# or by ID
pnpm payload passkeys:reset --collection users --id 42
```

It removes that user's passkeys and any registration in progress, and signs them out everywhere, so a session started with a planted passkey ends too. Their password is untouched. The command works with `enabled: false`, exits 1 on failure and 2 on a usage error, and logs `passkeys.reset`.

Deleting a user also removes their passkeys.

## Logging and privacy

The plugin writes one structured line through `payload.logger` per event, with the event name as `msg` and `event`:

| Event                             | Level | When                                                                                                                                                            |
| --------------------------------- | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `passkeys.registered`             | info  | A passkey was added.                                                                                                                                            |
| `passkeys.registration_failed`    | warn  | Adding a passkey failed (`reason` says why, for example `duplicate_credential_race` when a parallel registration stored the same credential first).             |
| `passkeys.renamed`                | info  | A passkey was renamed.                                                                                                                                          |
| `passkeys.removed`                | info  | A passkey was removed (`reason: signed_out_<n>` when other sessions ended too), or all of a user's passkeys when the user was deleted (`reason: user_deleted`). |
| `passkeys.signed_in`              | info  | A passkey sign-in succeeded.                                                                                                                                    |
| `passkeys.signed_in_while_locked` | info  | The account had a password lockout at the time.                                                                                                                 |
| `passkeys.sign_in_failed`         | warn  | A passkey sign-in failed, with `reason`.                                                                                                                        |
| `passkeys.unknown_credential`     | warn  | A sign-in presented a passkey the site doesn't know.                                                                                                            |
| `passkeys.counter_regression`     | warn  | A synced passkey reported a lower signature counter (expected when several devices share it).                                                                   |
| `passkeys.reauth_required`        | info  | Adding a passkey needed the password because the sign-in wasn't recent.                                                                                         |
| `passkeys.reauthenticated`        | info  | The password re-check succeeded.                                                                                                                                |
| `passkeys.reauth_failed`          | warn  | The password re-check failed.                                                                                                                                   |
| `passkeys.reset`                  | info  | `passkeys:reset` ran, with the counts removed.                                                                                                                  |

Lines carry the collection, the user ID, the first 8 characters of the credential ID and, where relevant, the AAGUID and a reason. They never contain challenges, signatures, public keys, user handles or email addresses. The plugin also logs `passkeys: ready` with the resolved RP ID and origins at boot.

**IP addresses** appear only on failures (`registration_failed`, `sign_in_failed`, `unknown_credential`, `reauth_failed`), truncated to /24 or /48 by default. Set `logging.ip` to `'none'` to leave them out or `'full'` to keep them whole.

Under UK GDPR an IP address is personal data. The lawful basis for logging it is legitimate interest in keeping the admin secure. The logs go wherever `payload.logger` sends them, so retention is your log retention: say so in your privacy notice.

## Security model

- **Stored:** public keys and metadata only. Nothing in the database lets anyone sign in.
- **User verification is required** at registration and sign-in: a passkey always means the device plus a fingerprint, face or device PIN.
- **Challenges** are 32 random bytes, valid for 5 minutes, used at most once (a unique insert, atomic on every adapter, before verification), and bound to the ceremony type, the collection, the user for registration, and the browser that asked, through an HttpOnly `SameSite=Strict` cookie (`__Host-` prefixed on HTTPS).
- **Origin and RP ID** come from the signed browser data and are checked against `origins` and `rpID`.
- **No account is named** at sign-in: the browser offers whichever passkeys it holds. Every failed passkey verification returns the same 400 `{ error: 'sign_in_failed' }` and takes similar time, including for an unknown passkey. The one exception: when the passkey's credential ID isn't stored, the response adds `unknownCredential: true`, so the browser can call `PublicKeyCredential.signalUnknownCredential` and the password manager drops the stale passkey. It reveals only that a credential ID the browser itself presented is unknown, never which accounts exist.
- **Collections stay apart:** every passkey records its collection, and every lookup matches collection and ID together, so `users` 7 and `customers` 7 can't use each other's passkeys.
- **Adding a passkey** needs a sign-in from the last `freshSessionMinutes`, or the password again through a real Payload sign-in with its lockout, so a stolen session cookie alone can't plant a passkey for later.
- **Removing a passkey** needs a signed-in session, not a recent one. The remove dialogue's "Also sign out everywhere else" box, ticked by default when the passkey was used in the last 24 hours, ends the sessions a planted passkey made. A session it ends can't be used again, even if a request that was already under way writes it back.
- **"Also sign out everywhere else" ends sessions, nothing more.** It doesn't change the password or turn off API keys, and Payload lets any signed-in session change the password or enable an API key without the current password. If you think someone else had your session, also change your password (Payload then signs out every other session) and check the account's API key.
- **Signature counters:** a device-bound passkey whose counter stops increasing is refused; a synced one is logged. This catches careless clones only: someone holding a cloned key can report a higher counter.
- **No secrets leave the server:** no response contains the password hash, salt, sessions, API key or user handle. The signed-in owner's `status` alone includes their WebAuthn user ID, which `signalAllAcceptedCredentials` needs.
- **Redirects** after sign-in stay within the admin.
- **Known limit:** the site-wide sign-in challenge cap means a flood of anonymous requests can make passkey sign-in answer "busy" for a few minutes. Password sign-in is unaffected; a `rateLimit` hook prevents it.

See [SECURITY.md](./SECURITY.md) to report a vulnerability.

## Translations

All admin text lives in Payload's i18n under the `passkeys` namespace. The keys and English strings are in [`src/translations/en.ts`](./src/translations/en.ts). Payload doesn't fall back to English for a missing key, so the plugin copies its English strings into every language in `i18n.supportedLanguages`, and into any language you translate, beneath your own strings. To change a string, or translate one, set it in your config:

```ts
export const i18n: Config['i18n'] = {
  translations: {
    en: { passkeys: { signInWithPasskey: 'Use a passkey' } },
  },
}
```

## Verifying this package

Every release is published from the repository's release workflow with npm trusted publishing: no npm token exists, and each version carries a provenance attestation. After installing, check the registry signatures and attestations of everything in your project:

```bash
npm audit signatures
```

It works on a pnpm-installed `node_modules` too. On [npmjs.com](https://www.npmjs.com/package/@the-digital-stride/payload-passkeys), the version's **Provenance** section should name the repository `The-Digital-Stride/payload-passkeys`, the workflow `.github/workflows/release.yml` and the commit it was built from. Don't install a version without it.

## Compatibility and support

Every pull request runs the integration suite, including the session contract tests, on:

| Payload | MongoDB | Postgres 17 | SQLite | Node                  |
| ------- | ------- | ----------- | ------ | --------------------- |
| 3.90.2  | yes     | yes         | yes    | 22                    |
| 3.91.0  | yes     | yes         | yes    | 22                    |
| 3.92.1  | yes     | yes         | yes    | 22                    |
| 3.93.0  | yes     | yes         | yes    | 22, and 24 on MongoDB |

Each night the contract tests and the integration suite also run against `payload@latest` and `payload@beta` on all three adapters. A `latest` failure opens an issue; `beta` is the next major and only informational. The end-to-end tests drive the admin in Chromium with a virtual authenticator, on Next.js 16.

Payload 4 is supported once it is stable. The code already follows its import rules, and the one module that touches Payload's undocumented session helpers is tested against every supported minor.

## Licence

MIT
