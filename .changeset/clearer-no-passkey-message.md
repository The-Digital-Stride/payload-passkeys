---
'@the-digital-stride/payload-passkeys': patch
---

When passkey sign-in ends without a passkey, the login page now says how to add one ("No passkey was used. If you haven’t added one yet, sign in with your password, then add one from your account.") instead of "Passkey sign-in was cancelled." The browser reports a dismissed prompt and a device with no passkey for the site the same way, so the message covers both. Sites that override `signInCancelled` keep their own text.
