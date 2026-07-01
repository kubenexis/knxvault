package auth

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// PoliciesFromClaims evaluates claim mappings and bound claims against JWT claims.
func PoliciesFromClaims(cfg *domainauth.OIDCConfig, claims jwt.MapClaims, rolePolicies []string) ([]string, error) {
	if cfg == nil {
		return rolePolicies, nil
	}
	if err := validateBoundClaims(cfg.BoundClaims, claims); err != nil {
		return nil, err
	}
	mapped := evaluateClaimMappings(cfg.ClaimMappings, claims)
	if len(cfg.ClaimMappings) > 0 && len(mapped) == 0 {
		return nil, common.New(common.ErrCodeForbidden, "no matching claim mapping")
	}
	return unionPolicies(rolePolicies, mapped), nil
}

func validateBoundClaims(bound map[string]string, claims jwt.MapClaims) error {
	for claim, want := range bound {
		got, ok := claimValueAsString(claims[claim])
		if !ok || got != want {
			return common.New(common.ErrCodeForbidden, fmt.Sprintf("required claim %q not satisfied", claim))
		}
	}
	return nil
}

func evaluateClaimMappings(mappings []domainauth.ClaimMapping, claims jwt.MapClaims) []string {
	out := make([]string, 0)
	for _, mapping := range mappings {
		values := claimValues(claims[mapping.Claim])
		for _, value := range values {
			if claimMatches(mapping, value) {
				out = append(out, mapping.Policies...)
			}
		}
	}
	return out
}

func claimMatches(mapping domainauth.ClaimMapping, value string) bool {
	if mapping.Regex {
		re, err := regexp.Compile(mapping.Match)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}
	return strings.EqualFold(value, mapping.Match)
}

func claimValues(raw any) []string {
	switch v := raw.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func claimValueAsString(raw any) (string, bool) {
	values := claimValues(raw)
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}

func unionPolicies(base, extra []string) []string {
	seen := make(map[string]struct{}, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, p := range append(append([]string(nil), base...), extra...) {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
