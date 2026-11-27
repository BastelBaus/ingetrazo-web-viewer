# Branches, releases and images

```
feature/*, fix/* --PR--> dev --> release/vX.Y --PR--> main --> tag vX.Y.Z
                          ^      (fixes only,          |
                          |       rc per push)         |
                          +------ back-merge PR <------+
hotfix/* (from main) --PR--> main --> tag vX.Y.Z+1 --> back-merge into dev
```

| Branch / tag | What it is | Image (`ghcr.io/bastelbaus/ingetrazo-web-viewer`) |
|---|---|---|
| `dev` | Integration branch, default branch, target of all feature PRs | `:dev`, `:dev-<sha>` (amd64) |
| any branch, manual *Publish* run | Try a branch in a container | `:br-<branch>` (amd64) |
| `release/vX.Y` | Release being stabilised: fixes only | `:X.Y.Z-rc.N`, `:rc` |
| `main` + tag `vX.Y.Z` | Released code only | `:X.Y.Z`, `:X.Y`, `:stable`, `:latest` |

Release images are built for amd64 and arm64, everything else for amd64 only (faster).
`dev-*` and `br-*` images are deleted after 30 days (*GHCR cleanup*).

## Everyday work

1. Branch off `dev`: `feature/…`, `fix/…`, `docs/…`.
2. Open a PR into `dev`. The title follows [Conventional Commits](https://www.conventionalcommits.org):
   `feat: …`, `fix: …`, `docs: …`, `ci: …`, `chore: …`, `feat!: …` for breaking changes.
   It becomes the commit message (squash merge) and the line in the release notes.
3. Sign off every commit (`git commit -s`). The required checks must pass (*DCO*, *smoke*, see
   [Branch protection](#branch-protection)); then the PR may merge, also by auto-merge.
   After the merge, *Publish* builds `:dev`.

To try an unmerged branch in a container: *Actions → Publish → Run workflow* on that branch → `:br-<branch>`.

## Release

1. *Actions → Release start → Run workflow*, version `X.Y`. This creates `release/vX.Y` from `dev`,
   tags `vX.Y.0-rc.1` (pre-release, image `:rc`) and opens the PR `release/vX.Y → main`.
2. Test the candidate. Fixes: PR into `release/vX.Y`; each merge makes the next `-rc.N`.
   `dev` goes on meanwhile.
3. When a candidate is good: merge the release PR with **Create a merge commit**.
   *Release finalize* tags `vX.Y.0` on `main`, writes the GitHub release, publishes `:stable` / `:latest`
   and opens the back-merge PR `main → dev`. Merge that one with a merge commit too.

The release branch may stay for patch releases: further pushes make `vX.Y.1-rc.N`, and the next
release PR from it becomes `vX.Y.1`.

## Hotfix

Branch `hotfix/…` off `main`, PR into `main`, merge (merge commit). *Release finalize* makes the next
patch release and the back-merge PR into `dev`.

## Merge methods

| PR | Method |
|---|---|
| feature → `dev`, fix → `release/*` | Squash |
| `release/*` → `main`, `hotfix/*` → `main`, back-merge `main` → `dev` | Merge commit |

## Branch protection

Nothing lands in `dev`, `release/*` or `main` without a pull request. The required checks get stricter the
closer a branch is to a release:

| Branch | Review | Required checks | Auto-merge |
|---|---|---|---|
| `dev` | – | *DCO*, *smoke* | allowed: merges as soon as the checks pass |
| `release/vX.Y` | – | *DCO*, *smoke* | allowed |
| `main` | 1 approval by a code owner; admins may bypass it | *DCO*, *smoke*, *full test* | no: a maintainer merges by hand |

On all three branches, force-push and deletion are blocked. Only maintainers may create or delete tags `v*`.

GitHub does not let anyone approve their own PR. So a maintainer (repository admin) may merge their own PR into
`main` without a review, and only the review can be bypassed: the required checks still apply. PRs from anyone
else, bots included, need the code owner's approval.

The checks:

- **DCO**: every commit in the PR carries a `Signed-off-by` line, or a remediation commit in the PR
  signs it off afterwards (see [CONTRIBUTING.md](../CONTRIBUTING.md#developer-certificate-of-origin-dco)).
  Merge commits are not checked. Takes seconds.
- **smoke**: shellcheck, unit tests, the image built for amd64, and a short end-to-end run of the MCP
  service and the viewer (`tests/smoke.sh`). Takes a few minutes, so it runs on every PR.
- **full test** (planned): the long run before a release. It runs only on PRs into `main`, i.e. release
  and hotfix PRs. Its scope is still open. Candidates: the image for amd64 and arm64, the smoke test on both, the
  auth, OAuth and folder smoke tests, and rendering a sample model with all its sheets and views.

### Status today

Not everything above is configured yet:

- Ruleset *DCO required (dev, main)*: PR required and *DCO* required on `dev` and `main`; force-push and
  deletion blocked. No bypass.
- Ruleset *main: smoke*: *smoke* required on `main`. No bypass.
- Ruleset *main: review (admins may bypass)*: 1 code-owner approval on `main`; repository admins may
  bypass it when they merge a PR.
- Open: *smoke* as a required check on `dev`; rules for `release/*` and tags `v*`; the *full test*
  workflow and making it required on `main`; `dev` as the default branch (it is still `main`).
- Auto-merge is switched on for the repository. GitHub cannot switch it off for one branch, so on `main`
  the required review keeps the merge in a maintainer's hands; nobody arms auto-merge on PRs into `main`.

## Repository settings this relies on

- Default branch `dev`; *Automatically delete head branches* on; squash and merge commits allowed;
  *Allow auto-merge* on.
- The branch protection above (rulesets).
- *Actions → General*: *Allow GitHub Actions to create and approve pull requests*.
- Optional secret `RELEASE_TOKEN` (fine-grained token: contents + pull requests read/write):
  release and back-merge PRs opened with it get CI runs; with the default token they do not.
