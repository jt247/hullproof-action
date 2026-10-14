#!/bin/sh
# Refreshes the two inputs the image is built from, from the sibling folders of the Hullproof lab: the Free kit files the engine reads
# at run time, and the engine tarball. Then update ENGINE_SHA256 in the Dockerfile with the value this prints.
# Usage: scripts/sync-inputs.sh /path/to/hullproof-engine-0.4.0.tgz
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
free="$here/../hullproof-free"
tgz=${1:?usage: sync-inputs.sh ENGINE_TARBALL}
mkdir -p "$here/kit/docs/hullproof" "$here/kit/tools/hullproof/ci" "$here/engine"
cp "$free/kit/docs/hullproof/security-controls.json" "$here/kit/docs/hullproof/"
for f in hullproof-gate.mjs hullproof-records-common.mjs validate-findings.mjs validate-surface-ledger.mjs; do
  cp "$free/kit/tools/hullproof/ci/$f" "$here/kit/tools/hullproof/ci/"
done
cp "$free/LICENSE" "$free/LICENSE-DOCS-CC-BY-SA-4.0.txt" "$free/LICENSING.md" "$free/NOTICE.md" "$here/kit/"
cp "$tgz" "$here/engine/"
echo "ENGINE_SHA256=$(shasum -a 256 "$here/engine/$(basename "$tgz")" | cut -d' ' -f1)"
