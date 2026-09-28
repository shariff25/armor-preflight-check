package model

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"time"
)

// NewRunID returns an ID of the form YYYYMMDD-HHMM-xxxx (UTC), used to
// name and label every object a run creates.
func NewRunID(now time.Time) string {
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		b = []byte{byte(now.Nanosecond() >> 8), byte(now.Nanosecond())}
	}
	return now.UTC().Format("20060102-1504") + "-" + hex.EncodeToString(b)
}

var runIDRE = regexp.MustCompile(`^[0-9]{8}-[0-9]{4}-[0-9a-f]{4}$`)

// ValidRunID reports whether s has the form NewRunID produces. Run IDs name
// namespaces, label selectors and bundle paths, so one read back from a file
// or a flag is checked before use.
func ValidRunID(s string) bool { return runIDRE.MatchString(s) }
