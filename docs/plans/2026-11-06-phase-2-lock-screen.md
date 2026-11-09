# Phase 2 Idle Lock Screen Implementation Plan (outline)

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. This is an outline: before executing, expand each task into numbered TDD steps in the style of `2026-11-06-v1-passkey-sign-in.md`, after the spikes in P0 have settled their questions.

**Goal:** A signed-in admin left idle for 15 minutes (configurable) is locked out on the server and sees a lock box. They unlock with their passkey or, without one, their password, and carry on without losing what is on screen.

**Architecture:** Locking is enforced on the server. `POST /passkeys/lock` revokes the current session, as core logout does, and sets an HttpOnly lock ticket: an HMAC over `{ collection, userId, lockedAt, exp }` with a key derived from `payload.secret` (review H2). Ticket-bound unlock endpoints mint a fresh session through v1's `mintSession` (passkey) or `loginOperation` (password). A client provider tracks activity across tabs. It shows an opaque, `inert`-making overlay, and drops it only after its own `/me` call confirms a live session (review M8).

**Tech Stack:** As v1, plus the Playwright `page.clock` API for idle and wake tests. No new runtime dependencies.

---

## Starting point

- v1 1.0.0 is released, and its contract tests are green on every supported minor.
- v1 already requires `useSessions` (it throws at config time otherwise, review H4). The lock depends on that: revoking a `sid` is what locks the server.
- `mintSession`, `reauthenticate`, `revokeSessions`, the challenge store, `passkeyEndpoint` guards, `logEvent` and `rateLimit` are reused unchanged.
- **New options**, all under `lock`:

  | Option | Default | Meaning |
  |---|---|---|
  | `lock.enabled` | `false` | Turn the lock on |
  | `lock.idleMinutes` | `15` | Idle time before locking |
  | `lock.onHidden` | `false` | Also lock when the tab is hidden |
  | `lock.collections` | the plugin's collections | Which collections are locked |
  | `lock.clearOnLock` | `'none'` | `'navigate-home'` moves to the dashboard before locking (review M8) |

  `resolveOptions` validates them, and refuses `lock.enabled` for a collection not in `collections`.

## Milestone P0: spikes (answer before building)

Each spike ends with a short decision record in `docs/decisions/` and a failing test, or a test that pins the observed behaviour. No production code.

### Spike S1: autosave and form submission while locked

**Question:** what Payload's admin does when autosave (drafts with `autosave: true`) or a manual save fires while the session is revoked, and whether the provider can pause it.

**Method:**
1. Add a `posts` collection with `versions: { drafts: { autosave: { interval: 2000 } } }` to the dev app.
2. In Playwright, type into a post, revoke the `sid` from the server, and keep typing.
3. Record:
   - the requests made;
   - the responses (expect 401/403 as anonymous);
   - what the UI shows (toast, error state, redirect to login?);
   - whether the form keeps its unsaved values.
4. Read the 3.90.2 source of the autosave element and the document form in `@payloadcms/ui` (`elements/Autosave`, `forms/Form`). Look for an exported way to pause autosave: the form's `disabled` or `processing` state, `useForm().setDisabled`, or the `isLocked`-style document locking.

**Output:** one of these, with the reason.
- **Pause:** the provider disables autosave and submission while locked, through an exported API.
- **Surface after unlock:** requests fail as anonymous while locked; after unlock the provider re-runs the last autosave and shows a toast if it was lost.
- **Hold:** the provider intercepts `fetch` to the API while locked and queues writes. Last resort, and probably refused: too invasive.

The test to keep: "edits made while locked are on the server after unlock" for drafts with autosave, on all three adapters.

### Spike S2: Payload 3.91+ activity-aware sessions

**Question:** 3.91 replaced `useAuth().tokenExpirationMs` with `authSession.expiresAt` and refreshes the token on activity. Does that refresh fight the lock? For example, does a refresh after the lock revive the session, or does a refresh in flight race the revocation?

**Method:**
1. Diff `@payloadcms/ui` `providers/Auth` between 3.90.2 and 3.93.x.
2. List every timer and every refresh trigger.
3. In Playwright on 3.93, idle until locked while a refresh is due, and check that `/me` stays anonymous.

**Output:**
- `src/components/lock/sessionExpiry.ts`. It feature-detects: `'authSession' in auth ? auth.authSession?.expiresAt : auth.tokenExpirationMs`. Never a version string.
- A contract test on each supported minor: "a refresh after lock does not restore the session". It must hold by construction, because the `sid` is gone and `refresh` requires it.
- The decision on whether the provider must stop Payload's own refresh timer while locked.

### Spike S3: how the admin reacts to a revoked session

**Question:** when the `sid` is revoked, does the admin's `useAuth` redirect to `/admin/login` on its next refresh or `/me`? That redirect would throw away the screen the lock is meant to keep.

**Method:** revoke the `sid` server-side with the admin open, and watch for redirects or remounts on refresh, on navigation, and on window focus.

**Output:**
- The interception strategy. Expected: the provider sets a locked state first, then revokes; while locked it renders the overlay and blocks the admin's own redirect. If that's not possible through exported APIs, the lock ends the session cleanly and the unlock flow restores the route afterwards from `sessionStorage`.
- A test that pins the behaviour.

### Spike S4: idle and wake detection across browsers

**Question:** are `BroadcastChannel`, `visibilitychange` and timer throttling consistent enough in Safari (macOS and iOS), Chrome and Firefox for "a laptop opened after an hour locks before showing anything"?

**Output:** the activity model:
- a wall-clock check on `visibilitychange`, `focus` and `pageshow`;
- a `setInterval` heartbeat;
- the last-activity time in `localStorage`, broadcast as a hint;
- manual check notes for each browser.

## Milestone P1: server

### Task 1: The lock ticket module (review H2)

- `src/server/lockTicket.ts`: `issueLockTicket({ collection, userId, lockedAt, exp }, secret)` and `readLockTicket(cookie, secret)`.
  - Key: HKDF-SHA256 from `payload.secret`, info `"@the-digital-stride/payload-passkeys lock-ticket v1"`. The domain separation means the key is never the JWT key.
  - Format: `base64url(json).base64url(hmac)`, compared with `timingSafeEqual`.
  - `exp` is the revoked session's `expiresAt`, so the lock can't outlive the sign-in.
- Cookie: `__Host-payload-passkeys-lock` (unprefixed on http), HttpOnly, `SameSite=Strict`, `Path=/`, no `Domain`, `Max-Age` = seconds to `exp`.
- **Unit tests:**
  - a round trip;
  - a tampered payload, a tampered MAC, the wrong secret;
  - expiry;
  - a v1 Payload JWT is refused as a ticket, and a ticket is refused by Payload's JWT strategy;
  - unknown fields are refused.

### Task 2: `POST /passkeys/lock`

- Signed-in (all v1 guards). It revokes the current `sid` with `revokeSessions({ only: [sid] })`, expires the Payload cookie (`generateExpiredPayloadCookie` from `payload/shared`), and sets the ticket.
- Idempotent: a second call with no session but a valid ticket answers 200.
- Logs `passkeys.locked`. Rate limit action `lock`.
- **Int tests (3 adapters):** after lock, `/me` is anonymous; refresh fails; the ticket is set; other sessions are untouched; an API key can't lock.

### Task 3: `POST /passkeys/unlock/options` and `/passkeys/unlock/verify`

- Both need a valid ticket.
- Options are discoverable with **empty `allowCredentials`**, so nothing is disclosed to whoever holds the screen. Challenge type `unlock`: add it to the challenge store's union, its own browser-key cookie, and the global anonymous cap.
- Verify is the v1 sign-in path, plus one check: the passkey row's owner must equal the ticket's `{ collection, userId }`. Otherwise refuse generically and log `passkeys.unlock_wrong_user`.
- On success, `mintSession` and clear the ticket.
- **Int tests:**
  - unlock with your own passkey;
  - refused with another user's passkey (same collection, and other collection with a colliding ID);
  - no ticket, an expired ticket or a tampered ticket;
  - replay;
  - the whole v1 rejection matrix, re-run through the unlock endpoints.

### Task 4: `POST /passkeys/unlock/password`

> **Amended 2026-11-09 (design D16, plan `2026-11-09-sso-sites.md` Decision 8):** skip this task when `reauthentication` is `'sign-in-again'`. In that mode the lock box shows "Sign in again" (logout, then the login page with `redirect`) to a user with no passkey, never a password field, and `unlock/password` is not registered, as `reauth` isn't in v1.

- Needs a valid ticket. The body is `{ password }` only: the identifier comes from the ticket's user on the server, never from the body.
- It runs `loginOperation`, as v1's `reauthenticate` does, so lockout and attempt counting apply.
- Rate limit action `unlock.password`, keyed by the ticket's user.
- **Int tests:**
  - a wrong password counts towards the lockout;
  - five wrong passwords lock the account;
  - an email in the body is ignored;
  - success clears the ticket.

### Task 5: Options, config checks and translations

- The `lock` options from "Starting point", with unit tests.
- New `passkeys` strings, UK English:

  | Key | Text |
  |---|---|
  | `lockedTitle` | "Locked" |
  | `lockedBody` | "You were away for a while, so we locked the admin." |
  | `unlockWithPasskey` | "Unlock with your passkey" |
  | `unlockWithPassword` | "Unlock with your password" |
  | `signOut` | "Sign out" |
  | `unlocking` | "Unlocking…" |
  | `unlockFailed` | "That didn’t unlock it. Try again." |

## Milestone P2: client

### Task 6: Activity tracker and idle timer

- `src/components/lock/activity.ts` is pure. Inputs: the events (pointer, key, scroll, focus, route change), a clock, and `idleMinutes`. Outputs: `lockDue`.
- The last activity is shared through `localStorage` and `BroadcastChannel`. A message is a **hint to re-check**, never state (review M8).
- **Unit tests with a fake clock:**
  - activity resets the timer;
  - activity in another tab resets it;
  - a wall-clock jump on wake locks at once;
  - `onHidden` locks when hidden;
  - the timer is throttled, not stopped, in background tabs.

### Task 7: `LockProvider` and the lock box

- Mounted inside v1's `PasskeysProvider`, only when `lock.enabled` and the user's collection is locked.
- **On `lockDue`:**
  1. If `clearOnLock === 'navigate-home'` and the current route is sensitive (users, API keys, the account page), `router.push(adminRoute)` first.
  2. Set the locked state.
  3. Make the app `inert`.
  4. Render the opaque overlay.
  5. Call `/passkeys/lock`.
  6. Broadcast `locked` as a hint.
- **The lock box:**
  - The title and body.
  - "Unlock with your passkey". Shown when WebAuthn is available and the user has a passkey; the provider already knows this from `status`.
  - "Unlock with your password". A password field; the email is never shown or sent.
  - "Sign out".
  - Focus is trapped inside it, and Esc does nothing.
- **Unlock:**
  1. On success, `setUser(body)`.
  2. Then the tab calls `/me` **itself**, and drops the overlay only when that confirms (review M8).
  3. Then broadcast `unlocked`. Other tabs re-check their own `/me` before dropping theirs.
- **Autosave and submission:** apply the S1 decision.
- **Session expiry display:** use S2's `sessionExpiry` shim.

### Task 8: Never store form state while locked

The provider writes nothing to `localStorage` or `sessionStorage` while locked except the lock hint. A test checks that storage holds no field values after a lock (review M8).

## Milestone P3: tests

### Task 9: Int matrix

Add the lock and unlock specs to the CI matrix (every minor × every adapter). Add the S2 contract test to the nightly run.

### Task 10: Playwright

Use `page.clock` to drive time and the CDP virtual authenticator from v1 Task 36. Cases:
1. Locks after `idleMinutes` with no activity, and `/api/users/me` is anonymous from the page.
2. Activity in a second tab keeps the first unlocked.
3. Unlock with the passkey: the overlay goes only after `/me` confirms, and the route and scroll position are kept.
4. Unlock with the password, and a wrong password shows `unlockFailed`.
5. Wake after an hour (`clock.fastForward`) shows the lock box before any content repaints.
6. Locking one tab locks the other, and unlocking one unlocks the other only after its own `/me` check.
7. `clearOnLock: 'navigate-home'` from the users list lands on the dashboard behind the lock.
8. A draft with autosave edited before the lock has its edits on the server after unlock (the S1 decision).
9. Another user's passkey can't unlock: simulate a second virtual authenticator credential for another user.

## Milestone P4: docs and release

### Task 11: README "Idle lock"

- The options, and how it works.
- **What the lock does not do** (review M8): it protects the server and every later request, not what is already rendered. Someone with DevTools at an unlocked-then-abandoned machine can still read the DOM behind the overlay, the router cache and local storage. For sensitive views, use `clearOnLock: 'navigate-home'`.
- How it interacts with Payload's `tokenExpiration` (the backstop when no tab is open) and with 3.91+ activity-aware sessions (S2).

### Task 12: Release 1.1.0

- A Changeset (minor).
- A security review of the phase-2 surface: ticket crypto, the unlock endpoints and the overlay rules, by the same separate reviewer process as v1.
- A trial on ianhancock.co.uk on a `1.1.0-rc` for a week before the release.
