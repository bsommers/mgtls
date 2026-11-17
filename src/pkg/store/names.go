package store

import (
	"fmt"
	"regexp"
	"strings"
)

// MaxNameLen bounds artifact names (CA, cert, SSH, ACME, target, unit names).
const MaxNameLen = 64

var validNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidName is the single allowlist for every artifact name that becomes a path
// component inside the store or a generated file/unit name. It rejects path
// separators, "..", leading dots, whitespace, control and shell metacharacters.
// SafePath alone is not enough: "../ca/root" stays inside BaseDir but lets one
// artifact type overwrite another's key material.
func ValidName(kind, name string) error {
	if name == "" {
		return fmt.Errorf("%s name is required", kind)
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("%s name %q exceeds %d characters", kind, name, MaxNameLen)
	}
	if !validNameRE.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("invalid %s name %q: use letters, digits, '.', '_' or '-' (must start with a letter or digit, no '..')", kind, name)
	}
	return nil
}
