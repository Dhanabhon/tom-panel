#!/bin/sh
# Container acceptance proxy: builds the Debian package (if dist/ is empty)
# and drills the install on a clean Ubuntu 24.04 image. The full VM drill
# with live systemd stays in scripts/acceptance-ubuntu-2404.sh.
set -eu

cd "$(dirname -- "$0")/.."

if ! ls dist/tompanel_*_amd64.deb >/dev/null 2>&1; then
    echo "==> no package in dist/; building one first"
    ./scripts/build-deb.sh 0.1.0-container
fi

echo "==> running container acceptance drill"
docker build --platform linux/amd64 --progress=plain \
    -t tompanel-acceptance:local -f Dockerfile.acceptance .
echo "==> acceptance proxy passed"
