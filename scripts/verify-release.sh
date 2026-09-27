#!/usr/bin/env bash
# Verifies a downloaded armor-preflight release, as a customer's security team
# would. Works on Linux and macOS; needs cosign (and jq for the probe image).
#
#   scripts/verify-release.sh DIR
#
# DIR holds checksums.txt, checksums.txt.sigstore.json and any of the other
# release files. Say who must have signed, one of:
#   COSIGN_PUBLIC_KEY=cosign.pub                   a release signed with a key
#   CERT_IDENTITY=<regexp> CERT_OIDC_ISSUER=<url>  a keyless release
#
# Checks, in order:
#   1. checksums.txt is signed by that identity
#   2. every other file in DIR is listed in checksums.txt and matches it
#   3. the probe image archive (if present) is the image in probe-image.txt
#   4. that image's signature, in its registry (skip with SKIP_REGISTRY=1
#      when the registry isn't reachable; step 3 still ties the archive to
#      the signed checksums)
#
# VERIFY_OFFLINE=1 skips the transparency log; only for CI snapshot builds.
set -euo pipefail

dir=${1:?usage: $0 DIR}
cd "$dir"

identity=()
if [ -n "${COSIGN_PUBLIC_KEY:-}" ]; then
  identity=(--key "$COSIGN_PUBLIC_KEY")
elif [ -n "${CERT_IDENTITY:-}" ] && [ -n "${CERT_OIDC_ISSUER:-}" ]; then
  identity=(--certificate-identity-regexp "$CERT_IDENTITY" --certificate-oidc-issuer "$CERT_OIDC_ISSUER")
else
  echo "verify-release: set COSIGN_PUBLIC_KEY, or CERT_IDENTITY and CERT_OIDC_ISSUER" >&2
  exit 2
fi
if [ "${VERIFY_OFFLINE:-}" = 1 ]; then
  identity+=(--insecure-ignore-tlog=true)
fi

echo "1. signature on checksums.txt"
cosign verify-blob "${identity[@]}" --bundle checksums.txt.sigstore.json checksums.txt

echo "2. checksums"
sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}
checked=0
for f in *; do
  case $f in checksums.txt | checksums.txt.sigstore.json) continue ;; esac
  [ -f "$f" ] || continue
  want=$(awk -v f="$f" '$2 == f || $2 == "*" f { print $1 }' checksums.txt)
  if [ -z "$want" ]; then
    echo "verify-release: $f is not listed in checksums.txt" >&2
    exit 1
  fi
  if [ "$(sha256 "$f")" != "$want" ]; then
    echo "verify-release: $f does not match checksums.txt" >&2
    exit 1
  fi
  echo "   ok  $f"
  checked=$((checked + 1))
done
if [ "$checked" -eq 0 ]; then
  echo "verify-release: no release files to check in $dir" >&2
  exit 1
fi

ref=
[ -f probe-image.txt ] && ref=$(cat probe-image.txt)
for archive in *_oci.tar; do
  [ -f "$archive" ] || continue
  echo "3. probe image archive"
  [ -n "$ref" ] || { echo "verify-release: $archive needs probe-image.txt" >&2; exit 1; }
  got=$(tar -xOf "$archive" index.json | jq -r '.manifests[0].digest')
  if [ "$got" != "${ref##*@}" ]; then
    echo "verify-release: $archive holds $got, not ${ref##*@}" >&2
    exit 1
  fi
  echo "   ok  $archive is $ref"
done

if [ -n "$ref" ] && [ "${SKIP_REGISTRY:-}" != 1 ]; then
  echo "4. signature on $ref"
  cosign verify "${identity[@]}" "$ref" >/dev/null
  echo "   ok"
fi
echo "release verified"
