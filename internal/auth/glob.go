package auth

import (
	"fmt"
	"strings"
)

// MatchResourceGlob returns true when resource matches a Vault-style glob pattern (W41-09).
func MatchResourceGlob(pattern, resource string) bool {
	if pattern == "*" || pattern == "*/*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return MatchResourceLegacy(pattern, resource)
	}
	return matchGlob(pattern, resource, 0, 0)
}

// MatchResourceLegacy is the pre-glob single-segment wildcard matcher.
func MatchResourceLegacy(pattern, resource string) bool {
	if pattern == "*" || pattern == "*/*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return resource == prefix || strings.HasPrefix(resource, prefix+"/")
	}
	return pattern == resource
}

func matchGlob(pat, str string, pi, si int) bool {
	for pi < len(pat) {
		switch pat[pi] {
		case '*':
			if pi+1 < len(pat) && pat[pi+1] == '*' {
				if pi+2 < len(pat) && pat[pi+2] == '/' {
					pi += 3
					for si <= len(str) {
						if matchGlob(pat, str, pi, si) {
							return true
						}
						if si == len(str) {
							break
						}
						next := strings.IndexByte(str[si:], '/')
						if next < 0 {
							si = len(str)
						} else {
							si += next + 1
						}
					}
					return false
				}
				pi += 2
				for si <= len(str) {
					if matchGlob(pat, str, pi, si) {
						return true
					}
					si++
				}
				return false
			}
			pi++
			for si <= len(str) {
				if matchGlob(pat, str, pi, si) {
					return true
				}
				si++
			}
			return false
		case '?':
			if si >= len(str) || str[si] == '/' {
				return false
			}
			pi++
			si++
		default:
			if si >= len(str) || pat[pi] != str[si] {
				return false
			}
			pi++
			si++
		}
	}
	return si == len(str)
}

// ValidateResourcePattern rejects ambiguous glob patterns at policy save time.
func ValidateResourcePattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("empty resource pattern")
	}
	if strings.Count(pattern, "**") > 1 {
		return fmt.Errorf("ambiguous pattern: multiple ** in %q", pattern)
	}
	return nil
}
