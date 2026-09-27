package settings

import (
	"fmt"
	"os"
)

// Secrets holds secret values read from the environment variables the
// settings file names. They are never written anywhere; the redaction layer
// registers them so they can be masked in every output.
type Secrets struct {
	RegistryPassword string
	StorageKey       string
}

// EnvLookup reads an environment variable; tests replace it.
type EnvLookup func(string) (string, bool)

// ResolveSecrets reads the secrets the settings name. A named variable that
// is unset is not an error: the checks that need it report skipped.
func (s *Settings) ResolveSecrets(lookup EnvLookup) Secrets {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	var sec Secrets
	if s.Registry.PasswordEnv != "" {
		sec.RegistryPassword, _ = lookup(s.Registry.PasswordEnv)
	}
	if s.Storage.CredentialsEnv != "" {
		sec.StorageKey, _ = lookup(s.Storage.CredentialsEnv)
	}
	return sec
}

// MissingEnv returns a reason if the environment variable named at the
// dotted settings path is unset or empty, or "" when it is set.
func (s *Settings) MissingEnv(path string, lookup EnvLookup) string {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	name := s.Get(path)
	if name == "" {
		return fmt.Sprintf("missing setting `%s`", path)
	}
	if v, ok := lookup(name); !ok || v == "" {
		return fmt.Sprintf("environment variable %s (named by `%s`) is not set", name, path)
	}
	return ""
}

// Values lists the non-empty secrets, for redaction.
func (sec Secrets) Values() []string {
	var out []string
	for _, v := range []string{sec.RegistryPassword, sec.StorageKey} {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
