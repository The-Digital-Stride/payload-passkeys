---
'@the-digital-stride/payload-passkeys': minor
---

Helpers for SSO hosts, from the first site to run 1.1.0 with Google sign-in:

- `refuseSignInUnless(isAllowed)` is a ready-made `beforeLogin` hook. It refuses disabled users on every sign-in (Payload's own login, passkeys, `signInVerifiedUser` and reset password). It also re-checks the saved record, so with database transactions on, a user disabled at the moment they sign in is refused and stays disabled. The check never receives the password hash, salt or sessions.
- `safeAdminRedirect` is exported from the main entry and from `/client`. It now refuses encoded slashes, backslashes and dots in the path, and takes an optional `maxLength` for hosts that carry the return path in a cookie.
- README fixes:
  - The offboarding sample cleans up on every save that disables a user, and says which databases run transactions.
  - The Vercel rate-limit sample sets a timeout and skips the `status` check.
  - The SSO callback sample deletes the state cookie on its own path and checks Google's `hd` and `email_verified`.
  - New testing and styling notes.
