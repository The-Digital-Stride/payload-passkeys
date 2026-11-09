# @the-digital-stride/payload-passkeys

## 1.1.0

### Minor Changes

- [#20](https://github.com/The-Digital-Stride/payload-passkeys/pull/20) [`25a3517`](https://github.com/The-Digital-Stride/payload-passkeys/commit/25a351762f07962b6e68e53e6670dac7ca889367) Thanks [@thedigitalstride](https://github.com/thedigitalstride)! - SSO sites: `reauthentication: 'sign-in-again'` replaces the password prompt with a "Sign in again" dialog for admins who sign in with SSO, `signInVerifiedUser` starts a Payload session from a host's own SSO callback, `resetPasskeys` is exported for offboarding hooks, `SignInRefused` is exported so hosts can check `error.reason`, and `onSignIn` receives `method` (`'passkey'` or `'sso'`). The reset command's message now names the collection.

## 1.0.0

### Major Changes

- [#13](https://github.com/The-Digital-Stride/payload-passkeys/pull/13) [`415f2a5`](https://github.com/The-Digital-Stride/payload-passkeys/commit/415f2a5ab172f61439581cc6366de8ce365bfcb5) Thanks [@thedigitalstride](https://github.com/thedigitalstride)! - First stable release. Admins of a Payload `>=3.90 <4` site, on MongoDB, Postgres or SQLite, can sign in to the admin with a passkey (Touch ID, Face ID, Windows Hello, an Android fingerprint, or the device's own PIN or password) alongside their email and password. They add, rename and remove passkeys from the Passkeys section on their account page, and are offered one after a password sign-in. See the README for requirements and setup.

### Patch Changes

- [#9](https://github.com/The-Digital-Stride/payload-passkeys/pull/9) [`04f262f`](https://github.com/The-Digital-Stride/payload-passkeys/commit/04f262fee57a9471746222321915eeb260681b87) Thanks [@thedigitalstride](https://github.com/thedigitalstride)! - When passkey sign-in ends without a passkey, the login page now says how to add one ("No passkey was used. If you haven’t added one yet, sign in with your password, then add one from your account.") instead of "Passkey sign-in was cancelled." The browser reports a dismissed prompt and a device with no passkey for the site the same way, so the message covers both. Sites that override `signInCancelled` keep their own text.

- [#8](https://github.com/The-Digital-Stride/payload-passkeys/pull/8) [`a257d3e`](https://github.com/The-Digital-Stride/payload-passkeys/commit/a257d3efec969062c8f632dada3160ef25530059) Thanks [@thedigitalstride](https://github.com/thedigitalstride)! - Passkeys no longer stay off until a restart when the MongoDB index check fails at boot for a passing reason, such as a dropped database connection while a deploy's servers start. A passkey request checks again, at most every 30 seconds per server, and passkey sign-in comes back once the indexes exist. Password sign-in was never affected.
