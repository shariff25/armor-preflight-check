package registry

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Reference is an image or chart reference: host/repo with a tag and/or digest.
type Reference struct {
	Host   string
	Repo   string
	Tag    string
	Digest string
}

// String renders the reference.
func (r Reference) String() string {
	s := r.Host + "/" + r.Repo
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

// Ref is the tag or digest to resolve, preferring the digest.
func (r Reference) Ref() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// ParseReference parses host/repo[:tag][@sha256:...]. The host is required:
// release manifests always name the registry.
func ParseReference(s string) (Reference, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "oci://")
	var r Reference
	if at := strings.LastIndex(s, "@"); at >= 0 {
		r.Digest = s[at+1:]
		s = s[:at]
		if !digestRE.MatchString(r.Digest) {
			return r, fmt.Errorf("invalid digest %q", r.Digest)
		}
	}
	slash := strings.Index(s, "/")
	if slash <= 0 {
		return r, fmt.Errorf("reference %q has no registry host", s)
	}
	r.Host, s = s[:slash], s[slash+1:]
	if !strings.ContainsAny(r.Host, ".:") && r.Host != "localhost" {
		return r, fmt.Errorf("reference %q has no registry host", r.Host+"/"+s)
	}
	if colon := strings.LastIndex(s, ":"); colon >= 0 {
		r.Tag, s = s[colon+1:], s[:colon]
	}
	r.Repo = s
	if r.Repo == "" {
		return r, fmt.Errorf("reference has no repository")
	}
	if r.Tag == "" && r.Digest == "" {
		return r, fmt.Errorf("reference %s has neither tag nor digest", r.Host+"/"+r.Repo)
	}
	return r, nil
}

// ParseManifestList reads a release manifest: one image reference per line,
// blank lines and # comments ignored.
func ParseManifestList(rd io.Reader) ([]Reference, error) {
	var out []Reference
	sc := bufio.NewScanner(rd)
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		r, err := ParseReference(t)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}
