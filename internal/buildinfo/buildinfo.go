// Package buildinfo holds values stamped into the binary at release time
// with -ldflags "-X github.com/shariff25/armor-preflight-check/internal/buildinfo.Version=...".
package buildinfo

var (
	// Version is the Preflight release version.
	Version = "0.1.0-dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// Date is the build timestamp in RFC 3339.
	Date = "unknown"
	// ProbeImage is the default probe image, pinned by digest at release
	// time (for example registry/armor-preflight-probe@sha256:...). Empty
	// in development builds; pass --probe-image instead.
	ProbeImage = ""
)
