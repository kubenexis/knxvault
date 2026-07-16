package audit

import (
	"fmt"
	"strings"
)

var sensitiveDetailKeys = map[string]struct{}{
	"password":          {},
	"passwd":            {},
	"secret":            {},
	"token":             {},
	"client_token":      {},
	"jwt":               {},
	"access_token":      {},
	"refresh_token":     {},
	"api_key":           {},
	"apikey":            {},
	"credential":        {},
	"credentials":       {},
	"private_key":       {},
	"private_key_pem":   {},
	"tls_key":           {},
	"access_key":        {},
	"secret_key":        {},
	"secret_id":         {},
	"unseal_key":        {},
	"master_key":        {},
	"connection_url":    {},
	"connection_string": {},
	"database_url":      {},
	"dsn":               {},
}

// SanitizeDetails redacts sensitive keys and credential-like string values before audit persistence.
func SanitizeDetails(details map[string]any) map[string]any {
	if details == nil {
		return nil
	}
	return sanitizeMap(details)
}

func sanitizeMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		if isSensitiveKey(key) {
			out[key] = "[REDACTED]"
			continue
		}
		out[key] = sanitizeValue(value)
	}
	return out
}

func sanitizeValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		return sanitizeMap(v)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = sanitizeValue(item)
		}
		return out
	case string:
		if looksLikeEmbeddedCredentials(v) {
			return "[REDACTED]"
		}
		return v
	default:
		return value
	}
}

func isSensitiveKey(key string) bool {
	_, ok := sensitiveDetailKeys[strings.ToLower(strings.TrimSpace(key))]
	return ok
}

func looksLikeEmbeddedCredentials(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	if strings.Contains(trimmed, "://") && strings.Contains(trimmed, "@") && strings.Contains(trimmed, ":") {
		beforeAt, _, ok := strings.Cut(trimmed, "@")
		if ok && strings.Count(beforeAt, ":") >= 2 {
			return true
		}
	}
	return false
}

// RejectSensitiveDetails returns an error when details contain non-redactable sensitive payloads.
func RejectSensitiveDetails(details map[string]any) error {
	if details == nil {
		return nil
	}
	return walkSensitive(details, "details")
}

func walkSensitive(value any, path string) error {
	switch v := value.(type) {
	case map[string]any:
		for key, nested := range v {
			if isSensitiveKey(key) {
				return fmt.Errorf("%s: sensitive key %q is not allowed in audit details", path, key)
			}
			if err := walkSensitive(nested, path+"."+key); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range v {
			if err := walkSensitive(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case string:
		if looksLikeEmbeddedCredentials(v) {
			return fmt.Errorf("%s: credential-like string is not allowed in audit details", path)
		}
	}
	return nil
}
