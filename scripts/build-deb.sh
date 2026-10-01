#!/bin/sh
# Reproducible Debian package build for TomPanel.
#
# Usage: scripts/build-deb.sh [version]
# The version defaults to a dev stamp; CI passes the tagged release.
# Artifacts land in dist/ (package + sha256). Two builds from the same
# commit produce byte-identical packages.
set -eu

cd "$(dirname -- "$0")/.."

VERSION="${1:-0.1.0~dev$(date -u +%Y%m%d)}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}"
[ -n "${SOURCE_DATE_EPOCH}" ] || SOURCE_DATE_EPOCH=946684800

echo "==> building tompanel ${VERSION} (SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH})"
docker build --progress=plain \
    --build-arg VERSION="${VERSION}" \
    --build-arg SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    --target artifact \
    --output type=local,dest=dist \
    -f Dockerfile.deb .

echo "==> artifacts:"
ls -l dist/tompanel_*_amd64.deb*
echo "==> verify reproducibility by re-running this script: hashes must match"
