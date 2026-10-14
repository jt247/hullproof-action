#!/bin/sh
# Builds the public engine tarball from the engine working copy (export, install the two dev dependencies, npm pack), copies the
# kit files and the tarball here, and updates ENGINE_SHA256 in the Dockerfile. Nothing is published.
# Usage: scripts/pack-engine.sh [path/to/hullproof-engine]   (default: ../hullproof-engine)
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
engine=${1:-$here/../hullproof-engine}
work=$(mktemp -d)
node "$engine/scripts/export-public.mjs" --out "$work/export" >/dev/null
(cd "$work/export" && npm ci --no-audit --no-fund >/dev/null 2>&1 && npm pack --pack-destination "$work" >/dev/null 2>&1)
rm -f "$here"/engine/*.tgz
sha=$("$here/scripts/sync-inputs.sh" "$work/hullproof-engine-0.4.0.tgz" | sed 's/^ENGINE_SHA256=//')
sed -i.bak "s/^ARG ENGINE_SHA256=.*/ARG ENGINE_SHA256=$sha/" "$here/Dockerfile" && rm "$here/Dockerfile.bak"
echo "engine tarball sha256 $sha"
