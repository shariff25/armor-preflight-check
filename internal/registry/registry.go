// Package registry is a minimal OCI distribution client: enough to check
// that credentials work and that manifests exist, without pulling layers.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// ErrUnauthorized means the registry rejected the credentials.
var ErrUnauthorized = errors.New("registry rejected the credentials")

// manifestAccept covers OCI and Docker manifests and indexes.
var manifestAccept = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

// Client talks to one registry host.
type Client struct {
	HTTP     *http.Client
	Host     string // host[:port], without scheme
	Username string
	Password string

	mu     sync.Mutex
	tokens map[string]string // scope -> bearer token
	basic  bool              // the registry uses Basic, not Bearer, auth
}

func (c *Client) base() string { return "https://" + c.Host }

// Ping checks that the registry is reachable and accepts the credentials:
// it authenticates against /v2/ and expects 200.
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, c.base()+"/v2/", "", "")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /v2/ returned %s", resp.Status)
	}
	return nil
}

// Manifest reports whether repo:ref (a tag or digest) exists, and its digest.
func (c *Client) Manifest(ctx context.Context, repo, ref string) (exists bool, digest string, err error) {
	u := fmt.Sprintf("%s/v2/%s/manifests/%s", c.base(), repo, url.PathEscape(ref))
	resp, err := c.do(ctx, http.MethodHead, u, "repository:"+repo+":pull", manifestAccept)
	if err != nil {
		return false, "", err
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, resp.Header.Get("Docker-Content-Digest"), nil
	case http.StatusNotFound:
		return false, "", nil
	}
	return false, "", fmt.Errorf("HEAD manifest returned %s", resp.Status)
}

// do sends a request, answering one auth challenge if the registry asks.
func (c *Client) do(ctx context.Context, method, rawURL, scope, accept string) (*http.Response, error) {
	send := func(auth string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		return c.HTTP.Do(req)
	}
	resp, err := send(c.cachedAuth(scope))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	auth, err := c.answer(ctx, challenge, scope)
	if err != nil {
		return nil, err
	}
	resp, err = send(auth)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		return nil, fmt.Errorf("%w (%s)", ErrUnauthorized, resp.Status)
	}
	return resp, nil
}

func (c *Client) cachedAuth(scope string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.basic {
		return c.basicAuth()
	}
	if t := c.tokens[scope]; t != "" {
		return "Bearer " + t
	}
	return ""
}

func (c *Client) basicAuth() string {
	if c.Username == "" && c.Password == "" {
		return ""
	}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(c.Username, c.Password)
	return req.Header.Get("Authorization")
}

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

// answer turns a WWW-Authenticate challenge into an Authorization header.
func (c *Client) answer(ctx context.Context, challenge, scope string) (string, error) {
	scheme, params, _ := strings.Cut(challenge, " ")
	switch strings.ToLower(scheme) {
	case "basic":
		c.mu.Lock()
		c.basic = true
		c.mu.Unlock()
		if c.Username == "" {
			return "", fmt.Errorf("%w: no credentials configured", ErrUnauthorized)
		}
		return c.basicAuth(), nil
	case "bearer":
	default:
		return "", fmt.Errorf("unsupported registry auth challenge %q", scheme)
	}
	p := map[string]string{}
	for _, m := range challengeParam.FindAllStringSubmatch(params, -1) {
		p[m[1]] = m[2]
	}
	realm, err := url.Parse(p["realm"])
	if err != nil || realm.Scheme != "https" {
		return "", fmt.Errorf("registry token realm %q is not https", p["realm"])
	}
	q := realm.Query()
	if p["service"] != "" {
		q.Set("service", p["service"])
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("%w (token endpoint returned %s)", ErrUnauthorized, resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %s", resp.Status)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	t := tok.Token
	if t == "" {
		t = tok.AccessToken
	}
	if t == "" {
		return "", errors.New("token endpoint returned no token")
	}
	c.mu.Lock()
	if c.tokens == nil {
		c.tokens = map[string]string{}
	}
	c.tokens[scope] = t
	c.mu.Unlock()
	return "Bearer " + t, nil
}
