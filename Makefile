PKG      := github.com/shariff25/agent-goverance-OS/armor-preflight
VERSION  ?= 0.1.0-dev
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X $(PKG)/internal/buildinfo.Version=$(VERSION) \
            -X $(PKG)/internal/buildinfo.Commit=$(COMMIT) \
            -X $(PKG)/internal/buildinfo.Date=$(DATE)
PLATFORMS := linux/amd64 linux/arm64

.PHONY: build test lint cross clean probe-image audit-lab release-snapshot

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/armor-preflight ./cmd/armor-preflight

test:
	go test ./...

lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "gofmt needed" && exit 1)
	go vet ./...

# Static binaries for the two release targets. Releases use
# scripts/release.sh, which also signs and writes checksums and SBOMs.
cross:
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; \
	  echo "building $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
	    -o bin/armor-preflight-$$os-$$arch ./cmd/armor-preflight || exit 1; \
	done

# The probe image used by `run cluster` (distroless, non-root).
probe-image:
	docker build -f deploy/probe/Dockerfile -t armor-preflight-probe:dev .

# R1.4 checks against a real kube-apiserver with audit logging (see the script).
audit-lab:
	scripts/audit-lab.sh

# A signed release of this commit in build/release (see scripts/release.sh).
# Needs PROBE_REPOSITORY, a registry to push to, and COSIGN_KEY for SIGN_OFFLINE.
release-snapshot:
	VERSION=$(VERSION) scripts/release.sh --snapshot

clean:
	rm -rf bin build dist preflight-out
