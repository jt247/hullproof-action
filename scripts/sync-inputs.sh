#!/bin/sh
# Refreshes the Free kit files the engine reads at run time (the controls file, the release gate and the record validators) with their
# licence files, from the sibling hullproof-free checkout, which must be on main with no local changes. The engine itself is not copied:
# the Dockerfile installs the exact npm version it pins. Records the Free commit in kit/SOURCE.txt.
# Usage: scripts/sync-inputs.sh
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
free="$here/../hullproof-free"
[ "$(git -C "$free" branch --show-current)" = "main" ] || { echo "hullproof-free is not on main" >&2; exit 1; }
[ -z "$(git -C "$free" status --porcelain)" ] || { echo "hullproof-free has local changes" >&2; exit 1; }
mkdir -p "$here/kit/docs/hullproof" "$here/kit/tools/hullproof/ci"
cp "$free/kit/docs/hullproof/security-controls.json" "$here/kit/docs/hullproof/"
for f in hullproof-gate.mjs hullproof-records-common.mjs validate-findings.mjs validate-surface-ledger.mjs; do
  cp "$free/kit/tools/hullproof/ci/$f" "$here/kit/tools/hullproof/ci/"
done
cp "$free/LICENSE" "$free/LICENSE-DOCS-CC-BY-SA-4.0.txt" "$free/LICENSING.md" "$free/NOTICE.md" "$here/kit/"
printf 'Copied from the Hullproof Free repository (https://github.com/jt247/hullproof-free) at commit %s.\n' "$(git -C "$free" rev-parse HEAD)" > "$here/kit/SOURCE.txt"
cat "$here/kit/SOURCE.txt"
