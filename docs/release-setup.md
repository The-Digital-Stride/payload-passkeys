# Release setup: repository and npm settings

The release workflow (`.github/workflows/release.yml`) depends on settings that live outside the repository, in GitHub's and npm's dashboards. Only a maintainer can change them. Work through this list once, before the first release, and again whenever the repository or the npm organisation changes hands.

Plan reference: Task 44 of `docs/plans/2026-11-06-v1-passkey-sign-in.md`; design §10.

## npm

- [ ] Claim the npm organisation `the-digital-stride`. If it is taken, fall back to `thedigitalstride` (design §12) and rename the package everywhere, starting with `package.json` and `src/shared/constants.ts`.
- [ ] Protect the npm account with a passkey.
- [ ] Find out whether npm lets you add a trusted publisher before the package exists. Sources disagree (checked 2026-11-06): most say the package must exist first; one says `npm trust` (npm 11.10.0 and later) can configure it for a package that hasn't been published. Then:
  - **If it can:** configure the trusted publisher (next item) and let the workflow make the first publish.
  - **If it can't:** publish the first version by hand, with 2FA, from a clean checkout of the release commit: `pnpm install --frozen-lockfile && pnpm build`, then `npm publish <tarball> --access public --tag next --provenance=false` on the tarball `pnpm pack` makes (`publishConfig.provenance` is true, and provenance can only be generated inside GitHub Actions). Never run `npm publish` in the repository itself: npm ignores `publishConfig.exports` and would ship a manifest pointing at `src/` (that is why `scripts/publish.mjs` publishes a packed tarball). A hand publish has no provenance, so make it a release candidate (`0.1.0-rc.0`), not a version anyone should keep. Revoke any token used.
- [ ] npm → the package → **Settings** → **Trusted publisher** → GitHub Actions: organisation `The-Digital-Stride`, repository `payload-passkeys`, workflow `release.yml`, environment `release`.
- [ ] Same page: set publishing access to "Require two-factor authentication and disallow tokens".

## GitHub repository

- [ ] **Settings → Environments → `release`:** add a required reviewer, and limit deployment branches to `main`. Note that `release.yml` runs on every push to `main` and uses this environment, so every merge to `main` waits for someone to approve the run, even when there is nothing to release (it then only opens or updates the version PR). Approve it, or reject runs you don't need. If that becomes a burden, the alternative is a separate job without the environment for the version PR, with only the publish behind approval; that is a workflow change, not a setting.
- [ ] **Branch protection on `main`:** pull requests required; one approving review; review from code owners; stale approvals dismissed; signed commits; no force pushes; administrators included. Required checks: `static`, every `int (payload …, …, node …)` job, `migrations`, `e2e` and CodeQL's `analyse`.
  - The integration cells for Payload 3.93.0 can't install before **2026-11-11**: 3.93.0 was published on 2026-11-04 and pnpm's `minimumReleaseAge` (7 days, `pnpm-workspace.yaml`) refuses anything younger. Until then those cells fail at install. Don't mark them required before they have passed once.
- [ ] **Tags:** protect `v*` and `@the-digital-stride/payload-passkeys@*` so only the release workflow creates them.
- [ ] **Decide on signed tags.** Design §10 asks for signed tags, but the workflow doesn't produce them: `changesets/action` creates **lightweight** tags through the GitHub API, which can't be signed. The choices are (a) accept unsigned tags, relying on npm provenance (which names the exact commit) and the protected environment, and amend design §10; (b) sign tags in the workflow with a key held as a secret, and push them with git instead of the API; or (c) create and sign each release tag by hand after the workflow publishes. Record the decision in `docs/design.md`.
- [ ] **Settings → Code security:** private vulnerability reporting (SECURITY.md sends reporters there), Dependabot alerts and security updates, secret scanning and push protection.
- [ ] **Settings → Actions → General:** "Require actions to be pinned to a full-length commit SHA" (or an allowlist), and workflow permissions "Read repository contents".
- [ ] Replace `<maintainer-handle>` in `.github/CODEOWNERS` with the real GitHub user or team.
- [ ] Create the issue label **`nightly`**. The nightly workflow's report job runs `gh issue create --label nightly`, which fails if the label doesn't exist.
- [ ] Protect the GitHub account of every maintainer with a passkey.

## Checks on the first runs

- [ ] **First `static` run:** compare the package count `npm audit signatures` reports with `pnpm list --depth Infinity --parseable | wc -l` (roughly; pnpm lists the workspace root too). The plan's claim that `npm audit signatures` works on a pnpm-installed tree was checked with npm 10.9.7; a count far below pnpm's means npm isn't seeing the tree, and the check proves less than it says.
- [ ] **First Dependabot run:** confirm Dependabot can update this repository with pnpm 11. Its pnpm 11 support is unconfirmed, and pnpm 11 reads its settings (`minimumReleaseAge`, `allowBuilds`, `engineStrict`, `saveExact`) from `pnpm-workspace.yaml`, not `.npmrc`. If the npm ecosystem PRs fail, keep the `github-actions` updates and bump npm dependencies by hand.
- [ ] **First release:** check on npmjs.com that the version shows provenance naming this repository, `release.yml` and the commit; run `npm audit signatures` in a consumer project.

## Optional

- [ ] `actionlint` isn't run in CI. Before changing a workflow, run it locally: `brew install actionlint`, then `actionlint` in the repository root.
