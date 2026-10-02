#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=${VERSION:-0.1.0-dev}
OUT_DIR=${OUT_DIR:-$ROOT/dist}

case "$VERSION" in
  ''|*[!A-Za-z0-9._-]*)
    echo "VERSION must contain only letters, numbers, dots, underscores, and hyphens" >&2
    exit 2
    ;;
esac

COMMIT=${COMMIT:-$(git -C "$ROOT" rev-parse --short=12 HEAD)}
BUILD_DATE=${BUILD_DATE:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}
LDFLAGS="-s -w -X github.com/comchan/socks-proxy-thru-wireguard/internal/version.Value=$VERSION -X github.com/comchan/socks-proxy-thru-wireguard/internal/version.Commit=$COMMIT -X github.com/comchan/socks-proxy-thru-wireguard/internal/version.Date=$BUILD_DATE"
mkdir -p "$OUT_DIR/.staging"

build_target() {
  os=$1
  arch=$2
  name="vpnfront_${VERSION}_${os}_${arch}"
  binary="$name"
  if [ "$os" = "windows" ]; then
    binary="$name.exe"
  fi
  stage="$OUT_DIR/.staging/$name"
  mkdir -p "$stage"
  echo "building $os/$arch"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$stage/$binary" "$ROOT/cmd/vpnfront"
  tar -czf "$OUT_DIR/$name.tar.gz" -C "$stage" "$binary"
}

build_target darwin amd64
build_target darwin arm64
build_target linux amd64
build_target linux arm64
build_target windows amd64
build_target windows arm64

checksum_file="$OUT_DIR/SHA256SUMS"
: > "$checksum_file"
for archive in "$OUT_DIR"/*.tar.gz; do
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$archive" | sed "s|$OUT_DIR/||" >> "$checksum_file"
  else
    sha256sum "$archive" | sed "s|$OUT_DIR/||" >> "$checksum_file"
  fi
done

echo "release artifacts written to $OUT_DIR"
