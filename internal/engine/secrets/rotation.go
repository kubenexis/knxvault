// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
)

// GenerateRotationValue produces a new secret value for the given generator.
func GenerateRotationValue(generator string) (map[string]any, error) {
	switch generator {
	case domainsecrets.GeneratorRandomPassword:
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("generate password: %w", err)
		}
		return map[string]any{
			"password": base64.RawURLEncoding.EncodeToString(raw),
		}, nil
	case domainsecrets.GeneratorScriptRef:
		return nil, fmt.Errorf("script_ref generator not supported in-process")
	default:
		return nil, fmt.Errorf("unknown generator %q", generator)
	}
}
