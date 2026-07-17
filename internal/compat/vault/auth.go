// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package vault

import "github.com/google/uuid"

// AuthResponse is a Vault Logical auth response (login endpoints).
// cert-manager reads client_token via vault.Secret.TokenID().
type AuthResponse struct {
	RequestID     string         `json:"request_id"`
	LeaseID       string         `json:"lease_id"`
	Renewable     bool           `json:"renewable"`
	LeaseDuration int            `json:"lease_duration"`
	Data          map[string]any `json:"data"`
	Warnings      any            `json:"warnings"`
	Auth          *AuthBlock     `json:"auth"`
}

// AuthBlock is the auth section of a Vault login response.
type AuthBlock struct {
	ClientToken   string            `json:"client_token"`
	Accessor      string            `json:"accessor"`
	Policies      []string          `json:"policies"`
	TokenPolicies []string          `json:"token_policies"`
	Metadata      map[string]string `json:"metadata"`
	LeaseDuration int               `json:"lease_duration"`
	Renewable     bool              `json:"renewable"`
	EntityID      string            `json:"entity_id"`
	TokenType     string            `json:"token_type"`
	Orphan        bool              `json:"orphan"`
}

// NewAuthResponse builds a Vault-shaped login success body.
func NewAuthResponse(clientToken string, policies []string, leaseSeconds int, renewable bool) AuthResponse {
	if policies == nil {
		policies = []string{}
	}
	if leaseSeconds < 0 {
		leaseSeconds = 0
	}
	return AuthResponse{
		RequestID:     uuid.NewString(),
		LeaseID:       "",
		Renewable:     renewable,
		LeaseDuration: leaseSeconds,
		Data:          map[string]any{},
		Warnings:      nil,
		Auth: &AuthBlock{
			ClientToken:   clientToken,
			Accessor:      uuid.NewString(),
			Policies:      policies,
			TokenPolicies: policies,
			Metadata:      map[string]string{},
			LeaseDuration: leaseSeconds,
			Renewable:     renewable,
			EntityID:      "",
			TokenType:     "service",
			Orphan:        true,
		},
	}
}

// KubernetesLoginRequest is POST .../auth/<mount>/login for Kubernetes auth.
type KubernetesLoginRequest struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

// AppRoleLoginRequest is POST .../auth/approle/login (or custom mount).
type AppRoleLoginRequest struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
}

// DetectLoginMethod classifies a login body for flexible mount handlers.
// Returns "approle", "kubernetes", or "".
func DetectLoginMethod(body map[string]any) string {
	if body == nil {
		return ""
	}
	if _, ok := body["role_id"]; ok {
		return "approle"
	}
	if _, ok := body["secret_id"]; ok {
		return "approle"
	}
	if _, ok := body["jwt"]; ok {
		return "kubernetes"
	}
	if _, ok := body["role"]; ok {
		// role alone is ambiguous; prefer kubernetes when jwt present handled above
		return "kubernetes"
	}
	return ""
}
