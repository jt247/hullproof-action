# Hullproof Action

Runs the Hullproof Engine on your repository and fails the check when a blocking finding is open. It uses code and configuration only. No model is called and no secret is needed.

This repository is private until the 0.5.0 release.

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
      - uses: jt247/hullproof-action@COMMIT_SHA
        with:
          fail-on: blocker
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        if: always()
        with:
          name: hullproof
          path: .hullproof/ci
          include-hidden-files: true
```

Pin the action to a full commit SHA, as you do for every other action.

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

## What it does and does not do

1. The edition is the Free edition: the BLOCKER and CRITICAL requirements. The check exits 1 when a finding at or above `fail-on` failed, 0 when none did, and 2 when it could not run.
2. A pull request from a fork gets a read only token and no secrets. For it the SARIF upload and the comment are skipped with a note, the job summary still shows the result, and the exit code is unchanged.
3. Use the `pull_request` event. Under `pull_request_target` the action stops with an error when the checkout is the head of the pull request, because that would run untrusted code with a write token and secrets.
4. If code scanning is not enabled for your repository, GitHub refuses the upload with HTTP 403. The action reports that as a notice, the check result is unchanged, and the SARIF file is in the workflow artifacts. On a private repository owned by a personal account, GitHub answered exactly that when this action was tested.
5. Text from your repository, such as file names and finding titles, is treated as data. It is escaped before it goes into a workflow command.
6. The model hunt is not part of this action. It needs a provider key and the Pro edition.

## What is pinned

The base image by digest. Node, Gitleaks, Trivy and OSV Scanner by version and sha256 for each CPU architecture. Semgrep and every Python package it needs by version and wheel hash (`semgrep.lock`). The engine by the sha256 of its tarball. Operating system packages (git, Python, certificates) come from the pinned Debian image through apt and are not hash pinned.

`kit/` holds the Free kit files the engine reads at run time (the controls file and the gate and validator scripts), copied from the Hullproof Free repository with their licences. `scripts/sync-inputs.sh` refreshes them.
