#!/usr/bin/env bash
# Signs a release file or a pushed image with cosign.
#
#   scripts/sign.sh blob FILE    writes FILE.sigstore.json (signature bundle)
#   scripts/sign.sh image REF    REF must be pinned by digest (repo@sha256:...)
#
# Which identity signs:
#   COSIGN_KEY set    that key: a file path, env://VAR, or a KMS URI such as
#                     azurekms://... (COSIGN_PASSWORD unlocks a file key)
#   COSIGN_KEY unset  keyless: Sigstore issues a short-lived certificate for
#                     the CI job's OIDC identity (GitHub Actions: id-token)
#
# SIGN_OFFLINE=1 keeps the signature out of the public transparency log. Only
# the snapshot build in CI uses it, with a throwaway key; releases never do.
set -euo pipefail

usage() { echo "usage: $0 blob FILE | image REPO@sha256:DIGEST" >&2; exit 2; }
[ $# -eq 2 ] || usage
kind=$1 target=$2

args=(--yes)
if [ -n "${COSIGN_KEY:-}" ]; then
  args+=(--key "$COSIGN_KEY")
elif [ "${SIGN_OFFLINE:-}" = 1 ]; then
  echo "sign.sh: SIGN_OFFLINE=1 needs COSIGN_KEY (keyless signing always uses the transparency log)" >&2
  exit 2
fi
if [ "${SIGN_OFFLINE:-}" = 1 ]; then
  args+=(--use-signing-config=false --tlog-upload=false)
fi

case $kind in
  blob)
    [ -f "$target" ] || { echo "sign.sh: $target is not a file" >&2; exit 2; }
    cosign sign-blob "${args[@]}" --bundle "$target.sigstore.json" "$target"
    chmod 0644 "$target.sigstore.json" # published alongside the file
    ;;
  image)
    # Signing a tag would sign whatever the tag points at when cosign looks.
    [[ $target == *@sha256:* ]] || { echo "sign.sh: $target is not pinned by digest" >&2; exit 2; }
    cosign sign "${args[@]}" "$target"
    ;;
  *) usage ;;
esac
