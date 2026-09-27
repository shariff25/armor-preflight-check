# Probe image for `armor-preflight run cluster`.
#
# A static Go binary on distroless, running as the distroless nonroot user
# (65532). It needs no shell, no package manager, no privileges and no
# Kubernetes API access. Build from the armor-preflight directory:
#
#   docker build -f deploy/probe/Dockerfile -t armor-preflight-probe:dev .
# Base images are pinned by digest so a rebuilt image cannot silently change
# underneath the release (supply chain). Update both digests deliberately.
FROM golang:1.24@sha256:d2d2bc1c84f7e60d7d2438a3836ae7d0c847f4888464e7ec9ba3a1339a1ee804 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=0.1.0-dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/probe ./cmd/probe

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/probe /probe
USER 65532:65532
ENTRYPOINT ["/probe"]
