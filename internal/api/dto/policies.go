// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package dto

// PolicyRequest creates or updates a policy.
type PolicyRequest struct {
	Effect       string         `json:"effect" binding:"required"`
	Resources    []string       `json:"resources" binding:"required"`
	Actions      []string       `json:"actions,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	Includes     []string       `json:"includes,omitempty"`
	Conditions   map[string]any `json:"conditions"`
}

// PolicyResponse returns a policy.
type PolicyResponse struct {
	Name         string         `json:"name"`
	Effect       string         `json:"effect"`
	Resources    []string       `json:"resources"`
	Actions      []string       `json:"actions"`
	Capabilities []string       `json:"capabilities,omitempty"`
	Includes     []string       `json:"includes,omitempty"`
	Conditions   map[string]any `json:"conditions"`
}

// RoleRequest creates or updates a role.
type RoleRequest struct {
	Policies                      []string    `json:"policies" binding:"required"`
	PolicyGroups                  []string    `json:"policy_groups,omitempty"`
	BoundServiceAccountNames      []string    `json:"bound_service_account_names,omitempty"`
	BoundServiceAccountNamespaces []string    `json:"bound_service_account_namespaces,omitempty"`
	AuthMethod                    string      `json:"auth_method,omitempty"`
	OIDC                          *OIDCConfig `json:"oidc,omitempty"`
	RequireMFA                    bool        `json:"require_mfa,omitempty"`
}

// OIDCConfig configures OIDC login for a role (W43-06).
type OIDCConfig struct {
	Issuer        string `json:"issuer"`
	Audience      string `json:"audience"`
	JWKSURL       string `json:"jwks_url"`
	MaxTTLSeconds int64  `json:"max_ttl_seconds"`
}

// RoleResponse returns a role binding.
type RoleResponse struct {
	Name                          string      `json:"name"`
	Policies                      []string    `json:"policies"`
	PolicyGroups                  []string    `json:"policy_groups,omitempty"`
	BoundServiceAccountNames      []string    `json:"bound_service_account_names,omitempty"`
	BoundServiceAccountNamespaces []string    `json:"bound_service_account_namespaces,omitempty"`
	AuthMethod                    string      `json:"auth_method,omitempty"`
	OIDC                          *OIDCConfig `json:"oidc,omitempty"`
	RequireMFA                    bool        `json:"require_mfa,omitempty"`
}

// PolicyImportRequest imports HCL policies (W41-08).
type PolicyImportRequest struct {
	HCL string `json:"hcl" binding:"required"`
}
