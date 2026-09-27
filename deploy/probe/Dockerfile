# Probe image for `armor-preflight run cluster`.
#
# A static Go binary on distroless, running as the distroless nonroot user
# (65532). It needs no shell, no package manager, no privileges and no
# Kubernetes API access. Build from the armor-preflight directory:
#
#   docker build -f deploy/probe/Dockerfile -t armor-preflight-probe:dev .
ARG GO_VERSION=1.24
FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=0.1.0-dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/probe ./cmd/probe

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/probe /probe
USER 65532:65532
ENTRYPOINT ["/probe"]
