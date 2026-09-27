// Package sgx is the seam for CC-05: generating an SGX DCAP quote on a node
// and verifying it against collateral fetched from the PCCS.
//
// Quote generation needs an enclave and Intel's DCAP libraries, so it
// cannot run in the standard distroless probe (D-5). The standard image
// uses Unsupported; an SGX probe image built with the toolchain Fortanix
// chooses (EGo, Gramine or Open Enclave) supplies a real Provider. The
// contract that image must meet is in docs/sgx-probe.md.
package sgx

import (
	"context"
	"errors"
)

// Provider generates and verifies quotes.
type Provider interface {
	// Quote returns a DCAP quote whose report data starts with reportData.
	Quote(ctx context.Context, reportData []byte) ([]byte, error)
	// Verify verifies a quote against collateral from the configured PCCS
	// and returns the result.
	Verify(ctx context.Context, quote []byte) (Verification, error)
}

// Verification is the outcome of verifying a quote.
type Verification struct {
	// TCBStatus is the platform TCB level status from the TCB info
	// collateral, for example "UpToDate" or "OutOfDate".
	TCBStatus string
	// ReportData is the report data carried in the quote.
	ReportData []byte
	// Advisories are Intel security advisory IDs that apply (INTEL-SA-...).
	Advisories []string
	// Collateral names where the collateral came from (the PCCS URL).
	Collateral string
}

// TCB level statuses (Intel SGX DCAP).
const (
	UpToDate                          = "UpToDate"
	SWHardeningNeeded                 = "SWHardeningNeeded"
	ConfigurationNeeded               = "ConfigurationNeeded"
	ConfigurationAndSWHardeningNeeded = "ConfigurationAndSWHardeningNeeded"
	OutOfDate                         = "OutOfDate"
	OutOfDateConfigurationNeeded      = "OutOfDateConfigurationNeeded"
	Revoked                           = "Revoked"
)

// Outcome is how CC-05 treats a TCB status.
type Outcome int

const (
	// Acceptable: the platform is up to date.
	Acceptable Outcome = iota
	// Attention: the quote verifies, but the platform needs configuration
	// or software hardening; Armor may accept it depending on policy.
	Attention
	// Unacceptable: out of date, revoked or unknown.
	Unacceptable
)

// Classify maps a TCB status to how CC-05 reports it.
func Classify(status string) Outcome {
	switch status {
	case UpToDate:
		return Acceptable
	case SWHardeningNeeded, ConfigurationNeeded, ConfigurationAndSWHardeningNeeded:
		return Attention
	}
	return Unacceptable
}

// ErrUnsupported is returned by a probe image without SGX support.
var ErrUnsupported = errors.New("this probe image cannot generate SGX quotes; run cluster mode with --sgx-probe-image (see docs/sgx-probe.md)")

// Unsupported is the Provider in the standard probe image.
type Unsupported struct{}

// Quote always fails with ErrUnsupported.
func (Unsupported) Quote(context.Context, []byte) ([]byte, error) { return nil, ErrUnsupported }

// Verify always fails with ErrUnsupported.
func (Unsupported) Verify(context.Context, []byte) (Verification, error) {
	return Verification{}, ErrUnsupported
}

// Fake is a Provider for tests.
type Fake struct {
	Status     string
	Advisories []string
	QuoteErr   error
	VerifyErr  error
	// WrongReportData makes the quote carry different report data.
	WrongReportData bool
}

// Quote returns a fake quote embedding reportData.
func (f *Fake) Quote(_ context.Context, reportData []byte) ([]byte, error) {
	if f.QuoteErr != nil {
		return nil, f.QuoteErr
	}
	if f.WrongReportData {
		reportData = []byte("stale")
	}
	return append([]byte("FAKEQUOTE:"), reportData...), nil
}

// Verify "verifies" a fake quote.
func (f *Fake) Verify(_ context.Context, quote []byte) (Verification, error) {
	if f.VerifyErr != nil {
		return Verification{}, f.VerifyErr
	}
	status := f.Status
	if status == "" {
		status = UpToDate
	}
	return Verification{TCBStatus: status, ReportData: quote[len("FAKEQUOTE:"):], Advisories: f.Advisories, Collateral: "https://global.acccache.azure.net/sgx/certification/v4/"}, nil
}
