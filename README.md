# @the-digital-stride/payload-passkeys

Passkey sign-in for the [Payload CMS](https://payloadcms.com) admin: Touch ID, Face ID, Windows Hello, Android fingerprint, or the device's own PIN, alongside email and password.

**Status: in design. Not yet published.** See `docs/design.md` for the design and `docs/plans/` for the build plan.

- Works with Payload `>=3.90 <4` on Node 22+, with MongoDB, Postgres or SQLite.
- Mints ordinary Payload sessions, so logout, refresh and session revocation work as normal.
- Stores only public keys: a database leak cannot be used to sign in.
- Password sign-in and forgot-password stay available.

Licence: MIT.
