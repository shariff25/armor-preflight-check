// Package azblob is a minimal Azure Blob Storage client: enough to write,
// read and delete one test blob (BAK-02) with either the storage account
// key (Shared Key) or a SAS token. The credential is never logged.
package azblob

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// APIVersion is the Blob service version requested.
const APIVersion = "2021-08-06"

// Client talks to one storage account.
type Client struct {
	HTTP        *http.Client
	AccountFQDN string // for example examplestorage.blob.core.windows.net
	// Credential is either the base64 account key or a SAS token.
	Credential string
	Now        func() time.Time
}

// Account is the account name: the first label of the FQDN.
func (c *Client) Account() string {
	name, _, _ := strings.Cut(c.AccountFQDN, ".")
	return name
}

// isSAS reports whether the credential is a SAS token rather than a key.
func (c *Client) isSAS() bool {
	return strings.Contains(c.Credential, "sig=")
}

// Put uploads a block blob.
func (c *Client) Put(ctx context.Context, container, blob string, data []byte) error {
	resp, err := c.do(ctx, http.MethodPut, container, blob, data, map[string]string{"x-ms-blob-type": "BlockBlob"})
	if err != nil {
		return err
	}
	return expect(resp, http.StatusCreated)
}

// Get downloads a blob.
func (c *Client) Get(ctx context.Context, container, blob string) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, container, blob, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// Delete deletes a blob.
func (c *Client) Delete(ctx context.Context, container, blob string) error {
	resp, err := c.do(ctx, http.MethodDelete, container, blob, nil, nil)
	if err != nil {
		return err
	}
	return expect(resp, http.StatusAccepted)
}

func (c *Client) do(ctx context.Context, method, container, blob string, body []byte, headers map[string]string) (*http.Response, error) {
	path := "/" + container + "/" + blob
	u := url.URL{Scheme: "https", Host: c.AccountFQDN, Path: path}
	if c.isSAS() {
		u.RawQuery = strings.TrimPrefix(c.Credential, "?")
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	req.Header.Set("x-ms-date", now().UTC().Format(http.TimeFormat))
	req.Header.Set("x-ms-version", APIVersion)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if len(body) > 0 {
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Type", "text/plain")
	}
	if !c.isSAS() {
		sig, err := Sign(req, c.Account(), c.Credential)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "SharedKey "+c.Account()+":"+sig)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, redactURL(err, c.Credential)
	}
	return resp, nil
}

// Sign computes the Shared Key signature for a request.
func Sign(req *http.Request, account, key string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("the storage credential is neither a SAS token nor a base64 account key")
	}
	mac := hmac.New(sha256.New, k)
	mac.Write([]byte(StringToSign(req, account)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// StringToSign builds the Shared Key string to sign (service version
// 2015-02-21 and later: an empty Content-Length when zero).
func StringToSign(req *http.Request, account string) string {
	h := req.Header
	length := ""
	if req.ContentLength > 0 {
		length = strconv.FormatInt(req.ContentLength, 10)
	}
	parts := []string{
		req.Method,
		h.Get("Content-Encoding"), h.Get("Content-Language"), length, h.Get("Content-MD5"), h.Get("Content-Type"),
		"", // Date: x-ms-date is used instead
		h.Get("If-Modified-Since"), h.Get("If-Match"), h.Get("If-None-Match"), h.Get("If-Unmodified-Since"), h.Get("Range"),
	}
	var msKeys []string
	for k := range h {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-ms-") {
			msKeys = append(msKeys, lk)
		}
	}
	sort.Strings(msKeys)
	var canon strings.Builder
	for _, k := range msKeys {
		canon.WriteString(k + ":" + strings.TrimSpace(h.Get(k)) + "\n")
	}
	resource := "/" + account + req.URL.EscapedPath()
	q := req.URL.Query()
	qkeys := make([]string, 0, len(q))
	for k := range q {
		qkeys = append(qkeys, strings.ToLower(k))
	}
	sort.Strings(qkeys)
	for _, k := range qkeys {
		vals := append([]string{}, q[k]...)
		sort.Strings(vals)
		resource += "\n" + k + ":" + strings.Join(vals, ",")
	}
	return strings.Join(parts, "\n") + "\n" + canon.String() + resource
}

func expect(resp *http.Response, code int) error {
	defer resp.Body.Close()
	if resp.StatusCode != code {
		return statusError(resp)
	}
	return nil
}

func statusError(resp *http.Response) error {
	msg := resp.Header.Get("x-ms-error-code")
	if msg == "" {
		msg = resp.Status
	}
	return fmt.Errorf("storage returned %s (%s)", resp.Status, msg)
}

// redactURL keeps a SAS token out of transport errors, which quote the URL.
func redactURL(err error, credential string) error {
	s := err.Error()
	if q := strings.TrimPrefix(credential, "?"); q != "" && strings.Contains(s, q) {
		return fmt.Errorf("%s", strings.ReplaceAll(s, q, "[REDACTED]"))
	}
	return err
}
