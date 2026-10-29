#!/usr/bin/env bash
# Run only for an explicitly requested public release. Does not upload anything.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
version=${1:-}
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || ! rg -Fq "versionName = \"$version\"" app/build.gradle.kts; then
    echo 'Usage: scripts/build-public-apks.sh X.Y.Z (must match versionName)' >&2
    exit 1
fi
./gradlew :app:assembleDebug -PpublicRelease=true
out="build/public-release/v$version"
mkdir -p "$out"
for abi in arm64-v8a x86_64 universal; do
    cp "app/build/outputs/apk/debug/app-$abi-debug.apk" "$out/hybrid-vpn-v$version-$abi.apk"
done
(cd "$out" && LC_ALL=C shasum -a 256 ./*.apk > SHA256SUMS)
printf 'Experimental debug-signed APKs and checksums: %s\n' "$out"
