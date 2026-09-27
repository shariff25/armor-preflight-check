// Package fsutil reads user-supplied files with a size limit, so a wrong
// path (a device, a huge log) cannot exhaust memory.
package fsutil

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// Size limits for the files Preflight reads.
const (
	MaxSettingsBytes = 1 << 20  // settings file
	MaxPEMBytes      = 1 << 20  // certificates
	MaxManifestBytes = 10 << 20 // release manifest
)

// ReadLimited reads at most max bytes of a regular file, and fails if the
// file is larger.
func ReadLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return b, nil
}

// ErrNotCertificates is returned when a PEM file holds anything other than
// certificates.
var ErrNotCertificates = errors.New("the file must contain only PEM CERTIFICATE blocks")

// ReadCertificatesPEM reads a PEM file that must contain only certificates.
// It refuses anything else, above all private keys, because the content is
// sent into the cluster.
func ReadCertificatesPEM(path string) ([]byte, error) {
	b, err := ReadLimited(path, MaxPEMBytes)
	if err != nil {
		return nil, err
	}
	rest, n := b, 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s: %w (found %q)", path, ErrNotCertificates, block.Type)
		}
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("%s: %w (found none)", path, ErrNotCertificates)
	}
	return b, nil
}
