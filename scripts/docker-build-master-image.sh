#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-opengfw-master:latest}"

cd "$ROOT_DIR"
echo "building docker image -> $IMAGE_NAME"
docker build -f docker/master/Dockerfile -t "$IMAGE_NAME" .
echo "done: $IMAGE_NAME"
