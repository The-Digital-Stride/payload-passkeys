# CLAUDE.md

Guidance for Claude Code in this repository.

## What this is

`@the-digital-stride/payload-passkeys`: a public, open-source Payload CMS 3 plugin that adds passkey sign-in (Touch ID, Face ID, Windows Hello, Android biometrics or the device PIN, via WebAuthn) to the Payload admin, alongside email and password. It works on any Payload 3 site (`>=3.90 <4`, Node 22+) and any database adapter (MongoDB, Postgres, SQLite). Phase 2 adds an idle lock screen.

**Status (2026-11-06): v1 built, not released.** Every task in the v1 plan is done on branch `v1-passkey-sign-in` (code, tests, CI and release workflows, README, SECURITY.md, the release checklist and the ianhancock.co.uk adoption instructions), except Task 44, which is the developer's dashboard work (`docs/release-setup.md`). Nothing is on GitHub or npm yet. The intended remote is `The-Digital-Stride/payload-passkeys`; the npm organisation `the-digital-stride` still has to be claimed.

## Read before working

| Doc | What it is |
|---|---|
| `docs/design.md` | The agreed brief, interview decisions (D1–D15) and design. Section 13 records where the build differs from the plan. |
| `docs/plans/2026-11-06-v1-passkey-sign-in.md` | v1 implementation plan, milestones M0–M6, bite-sized TDD tasks. Execute with `superpowers:executing-plans` (or subagent-driven development). |
| `docs/plans/2026-11-06-phase-2-lock-screen.md` | Outline plan for the idle lock screen. |
| `docs/research/external.md` | Standards, libraries, prior art, other CMSs, NIST, security pitfalls (sources dated). |
| `docs/research/payload-internals.md` | Payload 3.90.2 auth extension points with file and line references. |
| `docs/research/security-review.md` | Adversarial review of the design, and how each finding was resolved. |
| `docs/release-setup.md` | The GitHub and npm settings the release depends on (developer's checklist). |
| `docs/adoption-ianhancock.md` | Instructions for adopting the plugin on ianhancock.co.uk, for a session in that repo. |

Where a research doc and `design.md` disagree, `design.md` wins. **The code is the truth:** where any doc (the plan especially) describes something differently from `src/`, document what the code does and fix the doc.

The stored slug field on the `passkeys` and `passkey-challenges` collections is **`authCollection`**, not `collection` (Mongoose reserves `collection`). Plan snippets and the security review that query or read `collection` on those rows mean `authCollection`; function parameters named `collection` that hold a slug are unchanged.

## Working rules

- **One branch per task**, from an up-to-date `main`, named in kebab case.
- **Commit, never push.** The developer pushes. Conventional commits; Changesets drives versions (add a changeset with `pnpm changeset` for any user-facing change).
- **Use the `payload` skill** for any Payload work, and verify Payload behaviour against the installed source in `node_modules`, not memory. Never modify files in `node_modules`.
- **`src/server/mintSession.ts` is the only module allowed to touch Payload's undocumented auth exports.** Any change there needs the contract tests green on every supported Payload minor.
- **Server-only code** (SimpleWebAuthn server, endpoints, anything using `payload.secret`) must never be reachable from `src/exports/client.ts`; the client-import boundary test enforces it.
- **Spelling:** UK English for every string an admin reads (UI, errors, README for users); US English is fine in code, identifiers, comments and logs.
- **Never commit secrets.** Tests use throwaway secrets and in-memory or file databases.
- **Kill any dev server you start.**

## Code style

Prettier: single quotes, no semicolons, trailing commas, 100-character lines. ESM only.
