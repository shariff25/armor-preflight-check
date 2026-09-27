package model

import (
	"crypto/rand"
	"encoding/hex"
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
