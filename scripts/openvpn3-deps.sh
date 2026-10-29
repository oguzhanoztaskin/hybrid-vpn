#!/usr/bin/env bash
# Fetches and builds the native dependencies of the OpenVPN transport (ADR 0008)
# into third_party/ (git-ignored). Every download is pinned by SHA-256.
#
#   scripts/openvpn3-deps.sh [target...]     targets: android_arm64 android_amd64 host
#
# Without arguments it builds all three. The Go build picks the results up
# when it is run with -tags openvpn3 (the Gradle task does this automatically
# once third_party/ is populated). Requires: curl, tar, patch, perl, make, and
# for Android targets the NDK (ANDROID_NDK_HOME or the newest under the SDK).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TP="$ROOT/third_party"
DL="$TP/dl"
SRC="$TP/src"
API=24 # minSdk

OPENVPN3_VERSION=3.11.8
OPENVPN3_SHA256=ae9849055aabf9ac70885097c14aa7abbe00e80fc7703944fb0f7f0c5bfe425f
ASIO_VERSION=asio-1-24-0 # the version OpenVPN 3 pins, plus its patches
ASIO_SHA256=cbcaaba0f66722787b1a7c33afe1befb3a012b5af3ad7da7ff0f6b8c9b7a8a5b
LZ4_VERSION=1.10.0
LZ4_SHA256=537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b
OPENSSL_VERSION=3.5.9 # LTS
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

fetch() { # url file sha256
    local url=$1 file=$DL/$2 sum=$3
    if [ ! -f "$file" ]; then
        curl -sSfL -o "$file.part" "$url"
        mv "$file.part" "$file"
    fi
    if ! echo "$sum  $file" | shasum -a 256 -c - >/dev/null; then
        echo "checksum mismatch: $file" >&2
        rm -f "$file"
        exit 1
    fi
}

unpack() { # file dir
    [ -d "$SRC/$2" ] && return
    mkdir -p "$SRC/.tmp"
    tar -xzf "$DL/$1" -C "$SRC/.tmp"
    mv "$SRC/.tmp/$(tar -tzf "$DL/$1" | head -1 | cut -d/ -f1)" "$SRC/$2"
    rmdir "$SRC/.tmp"
}

sources() {
    mkdir -p "$DL" "$SRC"
    fetch "https://github.com/OpenVPN/openvpn3/archive/refs/tags/release/$OPENVPN3_VERSION.tar.gz" "openvpn3-$OPENVPN3_VERSION.tar.gz" $OPENVPN3_SHA256
    fetch "https://github.com/chriskohlhoff/asio/archive/$ASIO_VERSION.tar.gz" "$ASIO_VERSION.tar.gz" $ASIO_SHA256
    fetch "https://github.com/lz4/lz4/releases/download/v$LZ4_VERSION/lz4-$LZ4_VERSION.tar.gz" "lz4-$LZ4_VERSION.tar.gz" $LZ4_SHA256
    fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" "openssl-$OPENSSL_VERSION.tar.gz" $OPENSSL_SHA256
    unpack "openvpn3-$OPENVPN3_VERSION.tar.gz" openvpn3
    unpack "lz4-$LZ4_VERSION.tar.gz" lz4
    unpack "openssl-$OPENSSL_VERSION.tar.gz" openssl
    if [ ! -d "$SRC/asio" ]; then
        unpack "$ASIO_VERSION.tar.gz" asio
        for p in "$SRC"/openvpn3/deps/asio/patches/*.patch; do
            patch -s -p1 -d "$SRC/asio" <"$p"
        done
    fi
}

ndk() {
    if [ -n "${ANDROID_NDK_HOME:-}" ]; then echo "$ANDROID_NDK_HOME"; return; fi
    local sdk=${ANDROID_HOME:-$HOME/Library/Android/sdk}
    ls -d "$sdk"/ndk/* 2>/dev/null | sort -V | tail -1
}

openssl() { # target
    local target=$1 out=$TP/openssl/$1 build=$TP/build/openssl-$1 conf
    [ -f "$out/lib/libcrypto.a" ] && return
    case $target in
    android_arm64) conf="android-arm64 -D__ANDROID_API__=$API" ;;
    android_amd64) conf="android-x86_64 -D__ANDROID_API__=$API" ;;
    host)
        case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) conf=darwin64-arm64-cc ;;
        Darwin-x86_64) conf=darwin64-x86_64-cc ;;
        Linux-x86_64) conf=linux-x86_64 ;;
        Linux-aarch64) conf=linux-aarch64 ;;
        *) echo "unsupported host" >&2; exit 1 ;;
        esac ;;
    *) echo "unknown target $target" >&2; exit 1 ;;
    esac
    rm -rf "$build"
    mkdir -p "$build"
    (
        cd "$build"
        if [[ $target == android_* ]]; then
            local n; n=$(ndk)
            [ -d "$n" ] || { echo "no Android NDK found" >&2; exit 1; }
            export ANDROID_NDK_ROOT=$n
            PATH="$(echo "$n"/toolchains/llvm/prebuilt/*/bin):$PATH"
        fi
        # Static, no loadable modules (the legacy provider is built in), no apps/tests/docs.
        perl "$SRC/openssl/Configure" $conf no-shared no-module no-tests no-docs no-apps \
            --prefix="$out" --libdir=lib >/dev/null
        make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" build_libs >/dev/null
        make install_dev >/dev/null
    )
    rm -rf "$build"
}

sources
targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(android_arm64 android_amd64 host)
for t in "${targets[@]}"; do
    echo "openssl $OPENSSL_VERSION for $t"
    openssl "$t"
done
echo "done: $TP"
