#!/usr/bin/env bash
# Builds a complete, signed release into build/release/:
#
#   1. the probe image: built, pushed, signed (scripts/probe-release.sh)
#   2. the binaries for Linux and macOS, amd64 and arm64, with that image's
#      digest built in as the default probe image; archives, SBOMs and
#      checksums.txt (goreleaser)
#   3. checksums.txt signed (scripts/sign.sh). It lists every other file, so
#      verifying it and then the checksums verifies the whole release.
#
#   VERSION=1.2.3 PROBE_REPOSITORY=ghcr.io/example/armor-preflight-probe scripts/release.sh
#   scripts/release.sh --snapshot     same, for any commit (CI)
#
# Publishing build/release/ is left to the caller (the release workflow creates a
# draft GitHub release for a person to review and publish).
set -euo pipefail
cd "$(dirname "$0")/.."

snapshot=false
case "${1:-}" in
  --snapshot) snapshot=true ;;
  "") ;;
  *) echo "usage: $0 [--snapshot]" >&2; exit 2 ;;
esac

: "${VERSION:?set VERSION, for example 1.2.3}"
if ! [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "release: VERSION $VERSION is not a semantic version" >&2
  exit 2
fi
export VERSION

OUT=build/probe scripts/probe-release.sh
PROBE_IMAGE=$(cat build/probe/probe-image.txt)
export PROBE_IMAGE

if $snapshot; then
  goreleaser release --clean --snapshot
else
  # Tags in this repository carry a prefix (armor-preflight/v1.2.3), which
  # goreleaser can't parse, so the version is passed in and the tag checks
  # are skipped. The release workflow has already matched VERSION to the tag.
  GORELEASER_CURRENT_TAG=v$VERSION goreleaser release --clean --skip=publish,validate
fi

scripts/sign.sh blob dist/checksums.txt

# Exactly the files to publish, and nothing else from goreleaser's dist/.
rel=build/release
rm -rf "$rel"
mkdir -p "$rel"
cp dist/*.tar.gz dist/*.sbom.json dist/checksums.txt dist/checksums.txt.sigstore.json "$rel/"
cp build/probe/*_oci.tar build/probe/*.spdx.json build/probe/probe-image.txt "$rel/"
# Every listed file is present, and nothing unlisted (checksums.txt and its
# signature are the two files it can't list).
(cd "$rel" && sha256sum --check --strict --quiet checksums.txt)
files=("$rel"/*)
if [ $((${#files[@]} - 2)) -ne "$(wc -l <"$rel/checksums.txt")" ]; then
  echo "release: $rel holds files that checksums.txt doesn't list" >&2
  exit 1
fi
echo "release $VERSION built in $rel (probe image $PROBE_IMAGE)"
