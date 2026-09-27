# Probe image for `armor-preflight run cluster`.
#
# A static Go binary on distroless, running as the distroless nonroot user
# (65532). It needs no shell, no package manager, no privileges and no
# Kubernetes API access. Build from the armor-preflight directory:
#
#   docker build -f deploy/probe/Dockerfile -t armor-preflight-probe:dev .
# Base images are pinned by digest so a rebuilt image cannot silently change
# underneath the release (supply chain). Update both digests deliberately.
FROM golang:1.25.14@sha256:699337d620559a59b4a2bb298ad59611e535d2ee755a34cf2d2a98f37578dc80 AS build
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
