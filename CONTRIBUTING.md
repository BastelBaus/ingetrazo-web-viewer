# Contributing

Thanks for helping! Issues and pull requests are welcome. In short:

- Branch off **`dev`** and open your PR into `dev` (not `main`; `main` only holds released code).
- PR titles follow [Conventional Commits](https://www.conventionalcommits.org): `feat: …`, `fix: …`,
  `docs: …`, `ci: …`, `chore: …`; `feat!: …` marks a breaking change. The title ends up in the release notes.
- Sign off every commit (`git commit -s`, see [DCO](#developer-certificate-of-origin-dco) below).
- The required checks must pass: *DCO* and *smoke* (shellcheck, unit tests, image build, smoke test);
  PRs into `main` also need a code owner's review and the *full test*. See
  [Branch protection](docs/RELEASING.md#branch-protection). Run locally:
  `python3 -m unittest discover -s tests -p "test_*.py"` and `IMAGE=… tests/smoke.sh`; the full test:
  `FULL_TEST=1 python3 -m unittest discover -s tests -p "test_*.py"` and `IMAGE=… ENGINE_IMAGE=… tests/full.sh`.
  Quick checks go into the unit tests or `tests/smoke.sh` (every PR); slow ones into `tests/full.sh` or
  behind `FULL_TEST` (PRs into `main`). Security fixes come with a test in `tests/test_security.py`.
- **Auto-merge into `dev`:** a PR into `dev` from this repository merges by itself once *smoke*, *DCO* and
  *title* are green and it has no conflicts (`.github/workflows/automerge.yml`; it then starts *Publish* on
  `dev`). Not for drafts, forks or PRs labelled `no-automerge`; a conflict gets a comment instead.
- Fixes for a release being prepared go into `release/vX.Y`.

How branches, release candidates, releases and image tags work: [docs/RELEASING.md](docs/RELEASING.md).

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
instead of a contributor license agreement. You keep the copyright of your contribution; it is
licensed to everyone under the project's license, AGPL-3.0-or-later (see [LICENSE](LICENSE)).

By adding a `Signed-off-by` line to a commit, you certify the following:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### How to sign off

Add `-s` when you commit:

```sh
git commit -s -m "Fix the render queue priority"
```

This appends a line with the name and email from your git config:

```
Signed-off-by: Jane Doe <jane@example.com>
```

Use your real name (no pseudonyms or anonymous contributions). Every commit in a pull request
needs a sign-off; the `DCO` check on pull requests verifies it.

Forgot it? Fix the last commit with `git commit --amend -s --no-edit`, or all commits of your
branch with `git rebase --signoff origin/dev`, then force-push.

Already merged into `dev` (or another shared branch) and not to be rewritten? Add a
*remediation commit*: an empty commit, signed off itself, with one line per commit:

```sh
git commit --allow-empty -s -F - <<EOF
chore: DCO remediation

I, $(git config user.name) <$(git config user.email)>, hereby add my Signed-off-by to this commit: <sha>
EOF
```

The `DCO` check accepts a line only when the remediation commit is signed off by the same
`Name <email>`.

## Pull requests

- Keep changes focused; one topic per pull request.
- New source files start with `# SPDX-License-Identifier: AGPL-3.0-or-later`.
