#!/usr/bin/env bash
# Prepare only. Never pushes, changes repository visibility, or creates a GitHub release.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"
version=${1:-}
source_ref=${2:-HEAD}
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo 'Usage: scripts/prepare-public-release.sh X.Y.Z [verified-source-ref]' >&2
    exit 1
fi
if [[ -n $(git status --porcelain) ]]; then
    echo 'Commit verified changes before preparing a public release.' >&2
    exit 1
fi
source_commit=$(git rev-parse --verify "$source_ref^{commit}")
if ! git show "$source_commit:app/build.gradle.kts" | rg -Fq "versionName = \"$version\""; then
    echo "Source versionName does not match $version." >&2
    exit 1
fi
tag="v$version"
if git show-ref --verify --quiet "refs/tags/$tag"; then
    echo "$tag already exists; refusing to move a release tag." >&2
    exit 1
fi
release_ref=refs/heads/release/public
old=$(git rev-parse --verify "$release_ref" 2>/dev/null || true)
if [[ -n "$old" ]]; then
    # Only prepared snapshots may be parents; never a development commit.
    while read -r subject; do
        if [[ ! "$subject" =~ ^Release\ v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo 'release/public contains non-release commits; refusing to publish development history.' >&2
            exit 1
        fi
    done < <(git log --format=%s "$old")
fi
tree=$(git rev-parse "$source_commit^{tree}")
if [[ -n "$old" ]]; then
    snapshot=$(git commit-tree "$tree" -p "$old" -m "Release $tag")
else
    snapshot=$(git commit-tree "$tree" -m "Release $tag")
fi
git update-ref "$release_ref" "$snapshot" "$old"
git tag -a "$tag" "$snapshot" -m "Release $tag"
echo "Prepared $tag at $snapshot on release/public. No checkout or remote was changed."
echo 'Publish only when explicitly requested, using docs/RELEASING.md.'
