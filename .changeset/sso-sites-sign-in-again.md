---
'@the-digital-stride/payload-passkeys': minor
---

SSO sites: `reauthentication: 'sign-in-again'` replaces the password prompt with a "Sign in again" dialog for admins who sign in with SSO, `signInVerifiedUser` starts a Payload session from a host's own SSO callback, `resetPasskeys` is exported for offboarding hooks, `SignInRefused` is exported so hosts can check `error.reason`, and `onSignIn` receives `method` (`'passkey'` or `'sso'`). The reset command's message now names the collection.
