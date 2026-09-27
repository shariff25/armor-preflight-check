package azblob

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeStorage checks Shared Key signatures (with its own string-to-sign
// construction for the few headers this client sends) or a SAS signature,
// and stores blobs in memory.
type fakeStorage struct {
	account string
	key     []byte
	sas     string
	mu      sync.Mutex
	blobs   map[string]string
}

func (f *fakeStorage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.sas != "" {
		if r.URL.Query().Get("sig") == "" || r.URL.RawQuery != strings.TrimPrefix(f.sas, "?") {
			http.Error(w, "", http.StatusForbidden)
			return
		}
	} else {
		length, ctype := "", ""
		if r.ContentLength > 0 {
			length, ctype = r.Header.Get("Content-Length"), r.Header.Get("Content-Type")
		}
		ms := "x-ms-date:" + r.Header.Get("x-ms-date") + "\nx-ms-version:" + r.Header.Get("x-ms-version") + "\n"
		if bt := r.Header.Get("x-ms-blob-type"); bt != "" {
			ms = "x-ms-blob-type:" + bt + "\n" + ms
		}
		sts := r.Method + "\n\n\n" + length + "\n\n" + ctype + "\n\n\n\n\n\n\n" + ms + "/" + f.account + r.URL.Path
		mac := hmac.New(sha256.New, f.key)
		mac.Write([]byte(sts))
		want := "SharedKey " + f.account + ":" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if r.Header.Get("Authorization") != want {
			w.Header().Set("x-ms-error-code", "AuthenticationFailed")
			http.Error(w, "", http.StatusForbidden)
			return
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method {
	case http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		f.blobs[r.URL.Path] = string(b)
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet:
		b, ok := f.blobs[r.URL.Path]
		if !ok {
			w.Header().Set("x-ms-error-code", "BlobNotFound")
			http.Error(w, "", http.StatusNotFound)
			return
		}
		io.WriteString(w, b)
	case http.MethodDelete:
		delete(f.blobs, r.URL.Path)
		w.WriteHeader(http.StatusAccepted)
	}
}

func run(t *testing.T, f *fakeStorage, credential string) error {
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), AccountFQDN: strings.TrimPrefix(srv.URL, "https://"), Credential: credential}
	// The account name comes from the first label; the test server is an IP.
	f.account = c.Account()
	ctx := context.Background()
	if err := c.Put(ctx, "medusa", "armor-preflight-test.txt", []byte("hello")); err != nil {
		return err
	}
	got, err := c.Get(ctx, "medusa", "armor-preflight-test.txt")
	if err != nil {
		return err
	}
	if string(got) != "hello" {
		t.Fatalf("read back %q", got)
	}
	return c.Delete(ctx, "medusa", "armor-preflight-test.txt")
}

func TestSharedKeyRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	f := &fakeStorage{key: key, blobs: map[string]string{}}
	if err := run(t, f, base64.StdEncoding.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	if len(f.blobs) != 0 {
		t.Fatal("test blob not deleted")
	}
}

func TestWrongKeyIsRejected(t *testing.T) {
	f := &fakeStorage{key: []byte("right-key-right-key-right-key!!"), blobs: map[string]string{}}
	err := run(t, f, base64.StdEncoding.EncodeToString([]byte("wrong-key-wrong-key-wrong-key!!")))
	if err == nil || !strings.Contains(err.Error(), "AuthenticationFailed") {
		t.Fatalf("got %v", err)
	}
}

func TestSAS(t *testing.T) {
	sas := "?sv=2021-08-06&sp=rwd&sig=abc%2Bdef"
	f := &fakeStorage{sas: sas, blobs: map[string]string{}}
	if err := run(t, f, sas); err != nil {
		t.Fatal(err)
	}
}

func TestNotAKey(t *testing.T) {
	f := &fakeStorage{key: []byte("k"), blobs: map[string]string{}}
	if err := run(t, f, "not base64 !!"); err == nil || !strings.Contains(err.Error(), "neither a SAS token nor a base64 account key") {
		t.Fatalf("got %v", err)
	}
}

func TestStringToSignIncludesQuery(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://acct.blob.core.windows.net/c/b?comp=metadata&timeout=10", nil)
	req.Header.Set("x-ms-version", APIVersion)
	sts := StringToSign(req, "acct")
	if !strings.HasSuffix(sts, "x-ms-version:"+APIVersion+"\n/acct/c/b\ncomp:metadata\ntimeout:10") {
		t.Fatalf("%q", sts)
	}
}
