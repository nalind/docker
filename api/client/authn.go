package client

import (
	"fmt"
)

// ValidateAuthnOpt checks if a passed-in option value is a recognized
// authentication option.
func ValidateAuthnOpt(option string) (string, error) {
	return "", fmt.Errorf("invalid authentication option %s", option)
}
