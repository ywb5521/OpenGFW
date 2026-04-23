#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/dist}"
BINARY_PATH="$OUTPUT_DIR/opengfw-master"

mkdir -p "$OUTPUT_DIR"

cd "$ROOT_DIR"
echo "building opengfw-master -> $BINARY_PATH"
go build -trimpath -o "$BINARY_PATH" ./cmd/opengfw-master
echo "done: $BINARY_PATH"
