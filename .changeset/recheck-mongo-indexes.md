---
'@the-digital-stride/payload-passkeys': patch
---

Passkeys no longer stay off until a restart when the MongoDB index check fails at boot for a passing reason, such as a dropped database connection while a deploy's servers start. A passkey request checks again, at most every 30 seconds per server, and passkey sign-in comes back once the indexes exist. Password sign-in was never affected.
