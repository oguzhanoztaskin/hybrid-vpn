#!/usr/bin/env bash
# Builds the local OpenVPN test server for go/cmd/ovpnlab (macOS only): an
# OpenVPN 2 server from source plus utunshim, which lets it run without root.
# Output: third_party/ovpnlab/{openvpn,utunshim.dylib}. Test tooling only;
# nothing here ships in the app. Needs scripts/openvpn3-deps.sh host first
# (for OpenSSL).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TP="$ROOT/third_party"
OUT="$TP/ovpnlab"
OPENVPN_VERSION=2.7.8
OPENVPN_SHA256=c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36

[ "$(uname -s)" = Darwin ] || { echo "the lab server shim is macOS-only" >&2; exit 1; }
[ -f "$TP/openssl/host/lib/libcrypto.a" ] || { echo "run scripts/openvpn3-deps.sh host first" >&2; exit 1; }
mkdir -p "$TP/dl" "$TP/src" "$OUT"

file="$TP/dl/openvpn-$OPENVPN_VERSION.tar.gz"
[ -f "$file" ] || curl -sSfL -o "$file" "https://github.com/OpenVPN/openvpn/releases/download/v$OPENVPN_VERSION/openvpn-$OPENVPN_VERSION.tar.gz"
echo "$OPENVPN_SHA256  $file" | shasum -a 256 -c - >/dev/null || { echo "checksum mismatch: $file" >&2; rm -f "$file"; exit 1; }

clang -dynamiclib -O2 -Wall -o "$OUT/utunshim.dylib" "$ROOT/scripts/ovpnlab/utunshim.c"

if [ ! -x "$OUT/openvpn" ]; then
    src="$TP/src/openvpn-$OPENVPN_VERSION"
    rm -rf "$src"
    tar -xzf "$file" -C "$TP/src"
    (
        cd "$src"
        OPENSSL_CFLAGS="-I$TP/openssl/host/include" OPENSSL_LIBS="$TP/openssl/host/lib/libssl.a $TP/openssl/host/lib/libcrypto.a" \
            ./configure --disable-lzo --disable-lz4 --disable-plugins --disable-dco --disable-unit-tests >/dev/null
        make -j"$(sysctl -n hw.ncpu)" >/dev/null
    )
    cp "$src/src/openvpn/openvpn" "$OUT/openvpn"
fi
echo "built $OUT"
