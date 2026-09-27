#!/usr/bin/env bash
# Builds the probe image once for every release platform, as an OCI image
# archive, then pushes that archive, signs the pushed digest and writes an
# SBOM per platform. The archive is also a release file, for customers who
# mirror the image: what they load is byte for byte what the binary pins.
#
#   PROBE_REPOSITORY=ghcr.io/example/armor-preflight-probe VERSION=1.2.3 scripts/probe-release.sh
#
# Needs docker buildx (a builder that can export multi-platform OCI archives:
# the docker-container driver, or the docker driver with the containerd
# image store), crane, syft and cosign. Signing identity: see scripts/sign.sh.
#
# Writes to $OUT (default build/probe):
#   armor-preflight-probe_<version>_oci.tar                   the image, all platforms
#   armor-preflight-probe_<version>_linux_<arch>.spdx.json    SBOM per platform
#   probe-image.txt                                           <repository>@<digest>
set -euo pipefail
cd "$(dirname "$0")/.."

: "${PROBE_REPOSITORY:?set PROBE_REPOSITORY, for example ghcr.io/example/armor-preflight-probe}"
: "${VERSION:?set VERSION, for example 1.2.3}"
OUT=${OUT:-build/probe}
PLATFORMS=${PLATFORMS:-linux/amd64,linux/arm64}
name=armor-preflight-probe_${VERSION}
archive=$OUT/${name}_oci.tar

# The commit time, not the build time, so rebuilding a commit reproduces the
# same image digest. For the same reason there are no buildkit attestations:
# their provenance differs on every build. The SBOMs below are release files,
# and a keyless signature's certificate names the workflow and commit.
epoch=$(git log -1 --format=%ct)
revision=$(git rev-parse HEAD)

rm -rf "$OUT"
mkdir -p "$OUT/layout"
docker buildx build \
  --platform "$PLATFORMS" \
  --file deploy/probe/Dockerfile \
  --build-arg SOURCE_DATE_EPOCH="$epoch" \
  --provenance=false \
  --sbom=false \
  --label org.opencontainers.image.title=armor-preflight-probe \
  --label org.opencontainers.image.version="$VERSION" \
  --label org.opencontainers.image.revision="$revision" \
  --output "type=oci,dest=$archive,rewrite-timestamp=true" \
  .

tar -xf "$archive" -C "$OUT/layout"
digest=$(jq -r '.manifests | if length == 1 then .[0].digest else error("expected one image index") end' "$OUT/layout/index.json")

# Push the layout exactly as archived; the registry must report the same digest.
crane push "$OUT/layout" "$PROBE_REPOSITORY:$VERSION"
pushed=$(crane digest "$PROBE_REPOSITORY:$VERSION")
if [ "$pushed" != "$digest" ]; then
  echo "probe-release: pushed digest $pushed differs from archive digest $digest" >&2
  exit 1
fi
ref=$PROBE_REPOSITORY@$digest

IFS=, read -ra platforms <<<"$PLATFORMS"
for p in "${platforms[@]}"; do
  syft scan "oci-dir:$OUT/layout" --platform "$p" --quiet \
    --source-name armor-preflight-probe --source-version "$VERSION" \
    --output "spdx-json=$OUT/${name}_${p//\//_}.spdx.json"
done

scripts/sign.sh image "$ref"
echo "$ref" >"$OUT/probe-image.txt"
rm -rf "$OUT/layout"
echo "probe image: $ref"
