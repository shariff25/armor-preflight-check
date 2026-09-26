package exitcode

import (
	"errors"
	"fmt"
	"testing"
)

func TestFromError(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, Ready},
		{&Error{Code: NotReady, Err: errors.New("x")}, NotReady},
		{fmt.Errorf("wrapped: %w", &Error{Code: ReadyWithWarnings, Err: errors.New("x")}), ReadyWithWarnings},
		{errors.New("plain"), ToolError},
		{ToolFailure(errors.New("x")), ToolError},
	}
	for _, c := range cases {
		if got := FromError(c.err); got != c.want {
			t.Errorf("FromError(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

func TestCodesAreDistinct(t *testing.T) {
	seen := map[int]bool{}
	for _, c := range []int{Ready, ReadyWithWarnings, NotReady, ToolError} {
		if seen[c] {
			t.Fatalf("duplicate exit code %d", c)
		}
		seen[c] = true
	}
}
