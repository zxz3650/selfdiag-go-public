#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p dist
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  target_os=${target%/*}
  target_arch=${target#*/}
  echo "Building $target"
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build -trimpath -ldflags='-s -w' -o "dist/selfdiag-$target_os-$target_arch" ./cmd/selfdiag
done
