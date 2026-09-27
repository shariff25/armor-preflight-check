package redact

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/exitcode"
)

const secret = "s3cr3t/pa+ss=word!"

func TestMasksEveryForm(t *testing.T) {
	r := New(secret)
	for _, leaked := range []string{
		secret,
		base64.StdEncoding.EncodeToString([]byte(secret)),
		base64.RawURLEncoding.EncodeToString([]byte(secret)),
		url.QueryEscape(secret),
		url.PathEscape(secret),
	} {
		got := r.String("before " + leaked + " after")
		if strings.Contains(got, leaked) || got != "before "+Mask+" after" {
			t.Errorf("%q -> %q", leaked, got)
		}
	}
	if got := string(r.Bytes([]byte("x" + secret))); got != "x"+Mask {
		t.Errorf("Bytes: %q", got)
	}
}

func TestDockerAuthString(t *testing.T) {
	// A dockerconfigjson auth value is base64("user:password"); the
	// password alone is registered, so the combined string needs its own entry.
	auth := base64.StdEncoding.EncodeToString([]byte("user:" + secret))
	r := New(secret, "user:"+secret)
	if got := r.String(`{"auth":"` + auth + `"}`); strings.Contains(got, auth) {
		t.Fatalf("got %s", got)
	}
}

func TestEmptyAndNil(t *testing.T) {
	r := New("")
	if r.String("abc") != "abc" {
		t.Fatal("empty secret masked something")
	}
	var nilR *Redactor
	if nilR.String("abc") != "abc" || nilR.Error(nil) != nil {
		t.Fatal("nil redactor")
	}
}

func TestError(t *testing.T) {
	r := New(secret)
	base := exitcode.ToolFailure(errors.New("login failed for " + secret))
	err := r.Error(base)
	if strings.Contains(err.Error(), secret) {
		t.Fatal(err)
	}
	if exitcode.FromError(err) != exitcode.ToolError {
		t.Fatal("exit code lost")
	}
	plain := errors.New("fine")
	if r.Error(plain) != plain {
		t.Fatal("unchanged error should be returned as is")
	}
}

func TestWriterMasksAcrossWrites(t *testing.T) {
	var out bytes.Buffer
	w := NewWriter(New(secret), &out)
	half := len(secret) / 2
	w.Write([]byte("a " + secret[:half]))
	w.Write([]byte(secret[half:] + " b\nc " + secret))
	if strings.Contains(out.String(), "c ") {
		t.Fatal("partial line written early")
	}
	w.Close()
	if strings.Contains(out.String(), secret) || out.String() != "a "+Mask+" b\nc "+Mask {
		t.Fatalf("got %q", out.String())
	}
}

func TestMasksEscapedForms(t *testing.T) {
	secret := `a&b<c>"d'e\f`
	r := New(secret)
	for _, leaked := range []string{`a\u0026b\u003cc\u003e\"d'e\\f`, "a&amp;b&lt;c&gt;&#34;d&#39;e\\f"} {
		if got := r.String("x" + leaked + "y"); got != "x"+Mask+"y" {
			t.Errorf("%q -> %q", leaked, got)
		}
	}
}

func TestURL(t *testing.T) {
	for in, want := range map[string]string{
		"http://user:pass@proxy.example:3128": "http://proxy.example:3128",
		"https://admin@api.example:443/path":  "https://api.example:443/path",
		"http://proxy.example:3128":           "http://proxy.example:3128",
		"not a url":                           "not a url",
	} {
		if got := URL(in); got != want {
			t.Errorf("%s -> %s", in, got)
		}
	}
}
