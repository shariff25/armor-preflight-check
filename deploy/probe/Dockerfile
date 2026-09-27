# Probe image for `armor-preflight run cluster`.
#
# A static Go binary on distroless, running as the distroless nonroot user
# (65532). It needs no shell, no package manager, no privileges and no
# Kubernetes API access. Build from the armor-preflight directory:
#
#   docker build -f deploy/probe/Dockerfile -t armor-preflight-probe:dev .
#
# Releases build linux/amd64 and linux/arm64 in one buildx call
# (scripts/probe-release.sh). The build stage always runs on the build
# machine's own platform and cross-compiles, so no emulation is needed.
#
# Base images are pinned by digest so a rebuilt image cannot silently change
# underneath the release (supply chain). Update both digests deliberately.
FROM --platform=$BUILDPLATFORM golang:1.26.8@sha256:6c2a5538f964f1c82f97ad14988bf05de100d922d159d0e398b54c7b0ca0c6c9 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/probe ./cmd/probe

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/probe /probe
USER 65532:65532
ENTRYPOINT ["/probe"]
