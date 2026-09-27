package checks

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var versionNums = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

// parseVersion extracts MAJOR.MINOR[.PATCH] from strings like "v1.34.8",
// "1.34.8-aks" or an image tag "v0.15.2".
func parseVersion(s string) ([3]int, error) {
	m := versionNums.FindStringSubmatch(s)
	if m == nil {
		return [3]int{}, fmt.Errorf("no version in %q", s)
	}
	var v [3]int
	for i := 0; i < 3; i++ {
		if m[i+1] != "" {
			v[i], _ = strconv.Atoi(m[i+1])
		}
	}
	return v, nil
}

// versionAtLeast reports whether have >= min.
func versionAtLeast(have, min string) (bool, error) {
	h, err := parseVersion(have)
	if err != nil {
		return false, err
	}
	m, err := parseVersion(min)
	if err != nil {
		return false, err
	}
	for i := 0; i < 3; i++ {
		if h[i] != m[i] {
			return h[i] > m[i], nil
		}
	}
	return true, nil
}

// imageTag returns the tag of an image reference, without any digest.
func imageTag(image string) string {
	image, _, _ = strings.Cut(image, "@")
	slash := strings.LastIndex(image, "/")
	if colon := strings.LastIndex(image, ":"); colon > slash {
		return image[colon+1:]
	}
	return ""
}
