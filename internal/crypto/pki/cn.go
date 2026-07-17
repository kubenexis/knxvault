package pki

import (
	"fmt"
	"strings"
)

// ValidateCommonName rejects empty and control characters in certificate CNs.
// Also rejects '/' which historically broke OpenSSL -subj DN encoding (W50-08)
// and remains a sensible restriction for X.509 subject fields.
func ValidateCommonName(cn string) error {
	if strings.TrimSpace(cn) == "" {
		return fmt.Errorf("common name is required")
	}
	for _, r := range cn {
		if r == '/' || r == '\x00' || r < 0x20 {
			return fmt.Errorf("common name contains invalid characters")
		}
	}
	return nil
}
