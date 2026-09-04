#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

command -v docker >/dev/null 2>&1 || {
  echo "Docker is required. Install Docker and start its daemon." >&2
  exit 1
}

docker info >/dev/null 2>&1 || {
  echo "Docker is installed but its daemon is not available." >&2
  exit 1
}

exec docker build --platform linux/amd64 --progress=plain --target verify -f "$project_dir/Dockerfile.test" "$project_dir"
