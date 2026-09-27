package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
const key = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"

func write(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte(body), 0o600)
	return p
}

func TestReadLimited(t *testing.T) {
	if _, err := ReadLimited(write(t, strings.Repeat("x", 11)), 10); err == nil || !strings.Contains(err.Error(), "larger than 10 bytes") {
		t.Fatalf("got %v", err)
	}
	if b, err := ReadLimited(write(t, "ok"), 10); err != nil || string(b) != "ok" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := ReadLimited(t.TempDir(), 10); err == nil {
		t.Fatal("a directory was read")
	}
}

// Pen test: pointing trustedCaPath at a key bundle must not ship the key.
func TestReadCertificatesPEMRejectsKeys(t *testing.T) {
	for name, body := range map[string]string{"key": key, "cert then key": cert + key, "empty": "", "not pem": "hello"} {
		if _, err := ReadCertificatesPEM(write(t, body)); !errors.Is(err, ErrNotCertificates) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ReadCertificatesPEM(write(t, cert+cert)); err != nil {
		t.Fatal(err)
	}
}
