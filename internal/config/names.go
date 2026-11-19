package config

import (
	"fmt"
	"strings"
)

// Name canonicalizes an ordinary ASCII DNS host or service owner.
func Name(value string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if name == "" || len(name) > 253 {
		return "", fmt.Errorf("invalid DNS name %q", value)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS name %q", value)
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
				return "", fmt.Errorf("invalid DNS name %q", value)
			}
		}
	}
	return name + ".", nil
}
