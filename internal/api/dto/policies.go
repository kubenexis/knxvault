package dto

// PolicyRequest creates or updates a policy.
type PolicyRequest struct {
	Effect     string         `json:"effect" binding:"required"`
	Resources  []string       `json:"resources" binding:"required"`
	Actions    []string       `json:"actions" binding:"required"`
	Conditions map[string]any `json:"conditions"`
}

// PolicyResponse returns a policy.
type PolicyResponse struct {
	Name       string         `json:"name"`
	Effect     string         `json:"effect"`
	Resources  []string       `json:"resources"`
	Actions    []string       `json:"actions"`
	Conditions map[string]any `json:"conditions"`
}

// RoleRequest creates or updates a role.
type RoleRequest struct {
	Policies                      []string `json:"policies" binding:"required"`
	BoundServiceAccountNames      []string `json:"bound_service_account_names,omitempty"`
	BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces,omitempty"`
}

// RoleResponse returns a role binding.
type RoleResponse struct {
	Name                          string   `json:"name"`
	Policies                      []string `json:"policies"`
	BoundServiceAccountNames      []string `json:"bound_service_account_names,omitempty"`
	BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces,omitempty"`
}
