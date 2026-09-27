package protocol

import (
	"strings"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	in := Result{Version: Version, RunID: "r", NodePool: "sgxpool1", Node: "n", StartedAt: time.Unix(1, 0).UTC(),
		Stages: []Stage{{Target: "x:443", Stage: "tcp", OK: true, Detail: "connected"}}}
	line, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	log := "starting\n" + Sentinel + `{"version":"1","runId":"old"}` + "\nnoise\n" + line + "\n"
	got, err := Decode(log)
	if err != nil || got.RunID != "r" || got.Stages[0].Stage != "tcp" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestDecodeErrors(t *testing.T) {
	for log, want := range map[string]string{
		"no result here\n":           "no result line",
		Sentinel + "{not json\n":     "parse probe result",
		Sentinel + `{"version":"9"}`: "protocol version",
	} {
		if _, err := Decode(log); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v", log, err)
		}
	}
}
