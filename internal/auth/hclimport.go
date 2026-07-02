package auth

import (
	"fmt"
	"regexp"
	"strings"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

var (
	hclPathBlock = regexp.MustCompile(`(?s)path\s+"([^"]+)"\s*\{([^}]*)\}`)
	hclCapLine   = regexp.MustCompile(`capabilities\s*=\s*\[([^\]]*)\]`)
	hclQuoted    = regexp.MustCompile(`"([^"]*)"`)
)

// ImportHCLPolicy parses a Vault-style HCL policy subset into a KNXVault policy (W41-08).
func ImportHCLPolicy(name, hcl string) ([]domainauth.Policy, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("policy name is required")
	}
	matches := hclPathBlock.FindAllStringSubmatch(hcl, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no path blocks found in HCL")
	}
	var policies []domainauth.Policy
	for i, m := range matches {
		pathPattern := m[1]
		body := m[2]
		capMatch := hclCapLine.FindStringSubmatch(body)
		if capMatch == nil {
			return nil, fmt.Errorf("path %q missing capabilities", pathPattern)
		}
		var caps []string
		for _, q := range hclQuoted.FindAllStringSubmatch(capMatch[1], -1) {
			caps = append(caps, q[1])
		}
		if len(caps) == 0 {
			return nil, fmt.Errorf("path %q has empty capabilities", pathPattern)
		}
		policyName := name
		if len(matches) > 1 {
			policyName = fmt.Sprintf("%s-%d", name, i+1)
		}
		effect := domainauth.EffectAllow
		for _, c := range caps {
			if c == "deny" {
				effect = domainauth.EffectDeny
				break
			}
		}
		filtered := make([]string, 0, len(caps))
		for _, c := range caps {
			if c != "deny" {
				filtered = append(filtered, c)
			}
		}
		resource := strings.TrimPrefix(pathPattern, "/")
		policies = append(policies, domainauth.Policy{
			Name:         policyName,
			Effect:       effect,
			Resources:    []string{resource},
			Capabilities: filtered,
			Actions:      filtered,
		})
	}
	return policies, nil
}
