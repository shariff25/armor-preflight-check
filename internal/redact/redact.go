// Package redact masks secret values in everything Preflight writes:
// reports, the terminal, errors and the support bundle.
package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Mask replaces every secret.
const Mask = "[REDACTED]"

// Redactor holds the secrets to mask. The zero value masks nothing.
type Redactor struct {
	mu    sync.RWMutex
	forms []string // longest first, so a longer form is masked before a substring of it
}

// New returns a Redactor for the given secrets.
func New(secrets ...string) *Redactor {
	r := &Redactor{}
	r.Add(secrets...)
	return r
}

// Add registers secrets. Each is masked as written and in its base64 and
// URL-encoded forms, which is how secrets usually leak into error messages
// and docker config auth strings.
func (r *Redactor) Add(secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[string]bool{}
	for _, f := range r.forms {
		seen[f] = true
	}
	for _, s := range secrets {
		for _, f := range Forms(s) {
			if !seen[f] {
				seen[f] = true
				r.forms = append(r.forms, f)
			}
		}
	}
	sort.Slice(r.forms, func(i, j int) bool { return len(r.forms[i]) > len(r.forms[j]) })
}

// htmlTemplateEscaper mirrors html/template's escaping of text.
var htmlTemplateEscaper = strings.NewReplacer(`&`, "&amp;", `<`, "&lt;", `>`, "&gt;", `"`, "&#34;", `'`, "&#39;", "\x00", "\uFFFD")

// Forms lists the encodings of a secret that are masked: as written,
// JSON- and HTML-escaped (how it appears in result.json and report.html),
// base64 and URL-encoded.
func Forms(secret string) []string {
	if secret == "" {
		return nil
	}
	b := []byte(secret)
	jsonForm, _ := json.Marshal(secret) // Go escapes " \ < > & and controls
	forms := []string{
		secret,
		strings.Trim(string(jsonForm), `"`),
		html.EscapeString(secret),
		htmlTemplateEscaper.Replace(secret),
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
		url.QueryEscape(secret),
		url.PathEscape(secret),
	}
	out := forms[:0]
	seen := map[string]bool{}
	for _, f := range forms {
		if f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// String masks every registered secret in s.
func (r *Redactor) String(s string) string {
	if r == nil {
		return s
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, f := range r.forms {
		s = strings.ReplaceAll(s, f, Mask)
	}
	return s
}

// Bytes masks every registered secret in b.
func (r *Redactor) Bytes(b []byte) []byte {
	if r == nil {
		return b
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, f := range r.forms {
		b = bytes.ReplaceAll(b, []byte(f), []byte(Mask))
	}
	return b
}

// Error returns err with its message masked, or nil.
func (r *Redactor) Error(err error) error {
	if err == nil || r == nil {
		return err
	}
	masked := r.String(err.Error())
	if masked == err.Error() {
		return err
	}
	return &redactedError{msg: masked, err: err}
}

type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }

// Unwrap keeps errors.As working (for exit codes) without exposing the
// original message through Error.
func (e *redactedError) Unwrap() error { return e.err }

// Writer masks secrets in everything written through it. It buffers up to
// each newline so a secret split across two writes is still masked; call
// Flush (or Close) to write any trailing partial line.
type Writer struct {
	r   *Redactor
	w   io.Writer
	buf []byte
	mu  sync.Mutex
}

// NewWriter wraps w.
func NewWriter(r *Redactor, w io.Writer) *Writer { return &Writer{r: r, w: w} }

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	if i := bytes.LastIndexByte(w.buf, '\n'); i >= 0 {
		line := w.buf[:i+1]
		if _, err := w.w.Write(w.r.Bytes(append([]byte(nil), line...))); err != nil {
			return 0, err
		}
		w.buf = append(w.buf[:0], w.buf[i+1:]...)
	}
	return len(p), nil
}

// Flush writes any buffered partial line.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) == 0 {
		return nil
	}
	_, err := w.w.Write(w.r.Bytes(w.buf))
	w.buf = w.buf[:0]
	return err
}

// Close flushes.
func (w *Writer) Close() error { return w.Flush() }

// ErrUnredacted reports a secret-looking value that redaction cannot mask
// because it was never registered (for example, a private key).
var ErrUnredacted = errors.New("output contains an unregistered secret")

// URL returns s with any user:password removed, for URLs that are printed
// (a proxy from the environment, a kubeconfig server). Strings that do not
// parse as URLs with a host are returned unchanged.
func URL(s string) string {
	if !strings.Contains(s, "://") {
		// Proxy variables are often set without a scheme (user:pass@host:port).
		if at := strings.LastIndex(s, "@"); at >= 0 && !strings.ContainsAny(s[:at], "/ ") {
			return s[at+1:]
		}
		return s
	}
	u, err := url.Parse(s)
	if err != nil {
		// Unparseable, but may still carry credentials: drop everything
		// between the scheme and the last @ before the path.
		if i, at := strings.Index(s, "://"), strings.LastIndex(s, "@"); at > i {
			return s[:i+3] + s[at+1:]
		}
		return s
	}
	if u.User == nil {
		return s
	}
	u.User = nil
	return u.String()
}
