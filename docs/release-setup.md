# Release setup: repository and npm settings

The release workflow (`.github/workflows/release.yml`) depends on settings that live outside the repository, in GitHub's and npm's dashboards. Only a maintainer can change them. Work through this list once, before the first release, and again whenever the repository or the npm organisation changes hands.

Plan reference: Task 44 of `docs/plans/2026-11-06-v1-passkey-sign-in.md`; design §10.

## How the workflow is laid out

`release.yml` runs on every push to `main`, in three jobs, so the npm OIDC token never meets the repository's dependencies:

1. **`version`** (`contents: write`, `pull-requests: write`, no `id-token`): installs with `--ignore-scripts` and no cache, then `changesets/action` opens or updates the version PR. With no pending changesets it does nothing and the next job runs.
2. **`build`** (`contents: read`, no `id-token`, no cache): `pnpm install --frozen-lockfile`, `npm audit signatures` (through `scripts/audit-signatures.sh`, which retries only the intermittent `EMISSINGSIGNATUREKEY` lookup failure), unit tests, `pnpm build`, `pnpm pack`, then `node scripts/check-package.mjs` on that tarball. `node scripts/publish.mjs --tarball … --check` asks npm whether the version is there yet (0.0.0 never publishes). Only if it isn't does it upload the tarball and the changelog section as the `release` artifact.
3. **`publish`** (the `release` environment, `id-token: write`, `contents: write` for the tag): no `pnpm install`, no `node_modules`, no cache. It checks out `scripts/` only, installs npm 11.21.1, downloads the artifact (digest-checked), runs `node scripts/publish.mjs --tarball …` (re-checks the tarball's files and manifest, skips a version already on npm, publishes with `--provenance` on `latest`, or `next` for a prerelease), then `gh release create v<version>` on the release commit.

`test/unit/releaseWorkflow.spec.ts` fails if a change gives the OIDC token to another job or lets the publish job install anything.

**Accepted (2026-11-07):** the `version` job runs dependency code with a write token. `--ignore-scripts` stops install scripts, but `pnpm changeset version` then runs `@changesets/cli` and the changelog generator from `node_modules`, while `changesets/action` holds the job's `github.token` with `contents: write` and `pull-requests: write`. A compromised dependency there could push to a branch or edit the version PR. It can't publish (no `id-token` in that job, and `publish` needs the `release` environment's reviewer), and it can't reach `main` past branch protection. The packages are pinned in the lockfile and held back seven days by `minimumReleaseAge`.

## npm

- [ ] Claim the npm organisation `the-digital-stride`. If it is taken, fall back to `thedigitalstride` (design §12) and rename the package everywhere, starting with `package.json` and `src/shared/constants.ts`.
- [ ] Protect the npm account with a passkey.
- [ ] Find out whether npm lets you add a trusted publisher before the package exists. Sources disagree (checked 2026-11-06): most say the package must exist first; one says `npm trust` (npm 11.10.0 and later) can configure it for a package that hasn't been published. Then:
  - **If it can:** configure the trusted publisher (next item) and let the workflow make the first publish.
  - **If it can't:** publish the first version by hand, with 2FA, from a clean checkout of the release commit: `pnpm install --frozen-lockfile && pnpm build`, then `npm publish <tarball> --access public --tag next --provenance=false` on the tarball `pnpm pack` makes (`publishConfig.provenance` is true, and provenance can only be generated inside GitHub Actions). Never run `npm publish` in the repository itself: npm ignores `publishConfig.exports` and would ship a manifest pointing at `src/` (that is why `scripts/publish.mjs` publishes a packed tarball, and why `package.json`'s `prepublishOnly` refuses a directory publish; npm doesn't run it for a tarball). A hand publish has no provenance, so make it a release candidate (`0.1.0-rc.0`), not a version anyone should keep. Revoke any token used.
- [ ] npm → the package → **Settings** → **Trusted publisher** → GitHub Actions: organisation `The-Digital-Stride`, repository `payload-passkeys`, workflow `release.yml`, environment `release`.
- [ ] Same page: set publishing access to "Require two-factor authentication and disallow tokens".

## GitHub repository

- [ ] **Settings → Environments → `release`:** add a required reviewer, and limit deployment branches to `main`. Only the `publish` job uses this environment, and it runs only when the `build` job finds a version that isn't on npm yet, so an ordinary merge to `main` doesn't wait for approval.
- [ ] **Branch protection on `main`:** the release workflow runs on every push to `main` and doesn't run the CI checks itself (its `build` job runs only the unit tests), so it relies on this rule to keep anything that failed CI out of `main`, and so out of a release. Pull requests required; one approving review; review from code owners; stale approvals dismissed; signed commits; no force pushes; administrators included. Required checks: `static`, every `int (payload …, …, node …)` job, `migrations`, `e2e` and CodeQL's `analyse`.
  - The integration cells for Payload 3.93.0 can't install before **2026-11-11**: 3.93.0 was published on 2026-11-04 and pnpm's `minimumReleaseAge` (7 days, `pnpm-workspace.yaml`) refuses anything younger. Until then those cells fail at install. Don't mark them required before they have passed once.
- [ ] **Tags:** protect `v*` so only the release workflow creates them (the `publish` job runs `gh release create v<version>` with the job's `github.token`; allow GitHub Actions to bypass the rule).
- [ ] **Decide on signed tags.** Design §10 asks for signed tags, but the workflow doesn't produce them: `gh release create` makes a **lightweight** tag through the GitHub API, which can't be signed. The choices are (a) accept unsigned tags, relying on npm provenance (which names the exact commit) and the protected environment, and amend design §10; (b) sign tags in the workflow with a key held as a secret, and push them with git instead of the API; or (c) create and sign each release tag by hand after the workflow publishes. Record the decision in `docs/design.md`.
- [ ] **Settings → Code security:** private vulnerability reporting (SECURITY.md sends reporters there), Dependabot alerts and security updates, secret scanning and push protection.
- [ ] **Settings → Actions → General:** "Require actions to be pinned to a full-length commit SHA" (or an allowlist), and workflow permissions "Read repository contents".
- [x] Replace `<maintainer-handle>` in `.github/CODEOWNERS` with the real GitHub user or team (done: `@thedigitalstride`).
- [ ] Create the issue label **`nightly`**. The nightly workflow's report job runs `gh issue create --label nightly`, which fails if the label doesn't exist.
- [ ] Protect the GitHub account of every maintainer with a passkey.

## Checks on the first runs

- [ ] **First `static` run:** compare the package count `npm audit signatures` reports with `pnpm list --depth Infinity --parseable | wc -l` (roughly; pnpm lists the workspace root too). The plan's claim that `npm audit signatures` works on a pnpm-installed tree was checked with npm 10.9.7; a count far below pnpm's means npm isn't seeing the tree, and the check proves less than it says.
- [ ] **First Dependabot run:** confirm Dependabot can update this repository with pnpm 11. Its pnpm 11 support is unconfirmed, and pnpm 11 reads its settings (`minimumReleaseAge`, `allowBuilds`, `engineStrict`, `saveExact`) from `pnpm-workspace.yaml`, not `.npmrc`. If the npm ecosystem PRs fail, keep the `github-actions` updates and bump npm dependencies by hand.
- [ ] **First release:** check on npmjs.com that the version shows provenance naming this repository, `release.yml` and the commit; run `npm audit signatures` in a consumer project.

## Optional

- [ ] `actionlint` isn't run in CI. Before changing a workflow, run it locally: `brew install actionlint`, then `actionlint` in the repository root.
