# Hullproof Action

Runs the Hullproof Engine on your repository and fails the check when a blocking finding is open. It reads code and configuration only. No model is called and no secret is needed.

Version 0.5.0 installs the npm package `hullproof` at exactly 0.5.0 and checks its published integrity before it installs anything.

## Use

```yaml
name: hullproof
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  hullproof:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: jt247/hullproof-action@COMMIT_SHA # v0.5.0
        with:
          fail-on: blocker
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        if: always()
        with:
          name: hullproof
          path: .hullproof/ci
          include-hidden-files: true
```

Pin the action to a full commit SHA, the way you pin every other action, and keep the release in a trailing comment. When you update it, replace the SHA and the comment together. A tag can be moved; a commit SHA cannot.

## Image for GitLab, CircleCI, Bitbucket and Azure

The action runs from a container image that holds the engine and the scanners at pinned versions. The CI templates for GitLab CI, CircleCI, Bitbucket Pipelines and Azure Pipelines (in the Hullproof Engine repository, folder `ci-templates/`) run the same image. Replace the `REPLACE_WITH_THE_DIGEST_FROM_THE_RELEASE_NOTES` placeholder in the image line of the template with this digest:

```
ghcr.io/jt247/hullproof-action@sha256:edb214f237d56eff3433186a65a3a52fbff2a77413197a1f930ce2b641128f03
```

The image is built for linux/amd64 and linux/arm64. Check that you can pull it before you change your pipeline:

```
docker pull ghcr.io/jt247/hullproof-action@sha256:edb214f237d56eff3433186a65a3a52fbff2a77413197a1f930ce2b641128f03
```

The digest changes with each release of the action. The one above is for release 0.5.0. Newer digests are listed on the releases page of this repository, and the same digest is pinned in `action.yml`.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Folder to scan, inside the workspace |
| `stage` | empty | `LAUNCH`, `GROWTH` or `SCALE`. Empty reads `docs/security/STAGE.md`, else `LAUNCH` |
| `fail-on` | `blocker` | `blocker`, `critical`, `high`, `medium`, `low` or `none`. The check fails when a finding at or above this level failed |
| `upload-sarif` | `true` | Send `results.sarif` to code scanning. Needs `security-events: write` and code scanning on the repository |
| `comment` | `true` | Add or update one summary comment on pull requests. Needs `pull-requests: write` |
| `github-token` | `github.token` | Token for the upload and the comment |

Outputs are `exit-code`, `blocked` and `artifacts-path`. The folder holds `findings.json`, `report.md`, `results.sarif` and `pr-comment.md`. The same commit gives the same four files, byte for byte.

## Permissions

Least privilege, as in the example: `contents: read` for the checkout, `security-events: write` only if you upload the SARIF file, and `pull-requests: write` only if you want the comment. The action needs no secret.

## What it does and does not do

1. It runs the Free edition: the BLOCKER and CRITICAL requirements. The check exits 1 when a finding at or above `fail-on` failed, 0 when none did, and 2 when it could not run. The Pro edition and the model hunt are not part of this action.
2. A pull request from a fork gets a read only token and no secrets. For it the SARIF upload and the comment are skipped with a note, the job summary still shows the result, and the exit code is unchanged.
3. Use the `pull_request` event. Under `pull_request_target` the action stops with an error when the checkout is the head of the pull request, because that would run untrusted code with a write token and secrets.
4. If code scanning is not enabled for your repository, GitHub refuses the upload with HTTP 403. The action reports that as a notice, the check result is unchanged, and the SARIF file is in the workflow artifacts.
5. Text from your repository, such as file names and finding titles, is treated as data. It is escaped before it goes into a workflow command.
6. A passing check does not mean your requirements pass. Most requirements are settled by provider settings, a build or a test of the running app, and `report.md` lists what nothing settled.

## What is pinned

The base image by digest. Node, Gitleaks, Trivy and OSV Scanner by version and sha256 for each CPU architecture. Semgrep and every Python package it needs by version and wheel hash (`semgrep.lock`). The engine by exact npm version, sha512 integrity and sha1 shasum, checked by the build, which stops on a mismatch. Operating system packages (git, Python, certificates) come from the pinned Debian image through apt and are not hash pinned.

`kit/` holds the Free kit files the engine reads at run time (the controls file, the release gate and the record validators), copied from the Hullproof Free repository at the commit named in `kit/SOURCE.txt`. `scripts/sync-inputs.sh` refreshes them.

## Licences and notices

1. The action code (`src/`, `action.yml`, `Dockerfile`, `scripts/`, `test/`) is under the Apache License 2.0 (`LICENSE`), copyright Rare Phronesis Limited.
2. `kit/docs/hullproof/security-controls.json` is documentation under the Creative Commons Attribution ShareAlike 4.0 licence (`kit/LICENSE-DOCS-CC-BY-SA-4.0.txt`). It restates requirements from sources that ask for attribution, credited in `kit/NOTICE.md`. Copyright Rare Phronesis Limited. If you redistribute that file or a changed copy, keep the notice and the same licence. The gate and validator scripts in `kit/tools/` are under the Apache License 2.0. `kit/LICENSING.md` says which licence covers which path.
3. The image holds other programs under their own licences, called as separate programs: Semgrep (LGPL-2.1), Gitleaks (MIT), Trivy and OSV Scanner (Apache-2.0), Node.js (MIT) and Debian packages. The `hullproof` package is Apache-2.0.
