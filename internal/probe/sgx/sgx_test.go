package sgx

import (
	"context"
	"errors"
	"testing"
)

func TestClassify(t *testing.T) {
	for s, want := range map[string]Outcome{
		UpToDate: Acceptable, SWHardeningNeeded: Attention, ConfigurationNeeded: Attention, ConfigurationAndSWHardeningNeeded: Attention,
		OutOfDate: Unacceptable, OutOfDateConfigurationNeeded: Unacceptable, Revoked: Unacceptable, "": Unacceptable, "Weird": Unacceptable,
	} {
		if got := Classify(s); got != want {
			t.Errorf("%q: %v", s, got)
		}
	}
}

func TestUnsupported(t *testing.T) {
	if _, err := (Unsupported{}).Quote(context.Background(), nil); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}
