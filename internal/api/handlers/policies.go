// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/service"
)

// PolicyHandler serves RBAC policy and role endpoints.
type PolicyHandler struct {
	svc         *service.PolicyService
	oidcEnabled bool // M-DTP-2: reject OIDC role config when auth method disabled
}

// NewPolicyHandler constructs a PolicyHandler.
func NewPolicyHandler(svc *service.PolicyService) *PolicyHandler {
	return &PolicyHandler{svc: svc, oidcEnabled: true}
}

// SetOIDCEnabled controls whether role OIDC config is accepted (M-DTP-2).
func (h *PolicyHandler) SetOIDCEnabled(enabled bool) {
	if h != nil {
		h.oidcEnabled = enabled
	}
}

// PutPolicy handles PUT /sys/policies/:name.
func (h *PolicyHandler) PutPolicy(c *gin.Context) {
	var req dto.PolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	actions := auth.NormalizeCapabilities(req.Capabilities, req.Actions)
	policy := &domainauth.Policy{
		Name:         c.Param("name"),
		Effect:       domainauth.Effect(req.Effect),
		Resources:    req.Resources,
		Actions:      actions,
		Capabilities: actions,
		Includes:     req.Includes,
		Conditions:   req.Conditions,
	}
	if err := h.svc.SavePolicy(c.Request.Context(), policy); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

// GetPolicy handles GET /sys/policies/:name.
func (h *PolicyHandler) GetPolicy(c *gin.Context) {
	policy, err := h.svc.GetPolicy(c.Request.Context(), c.Param("name"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.PolicyResponse{
		Name:         policy.Name,
		Effect:       string(policy.Effect),
		Resources:    policy.Resources,
		Actions:      policy.Actions,
		Capabilities: policy.Capabilities,
		Includes:     policy.Includes,
		Conditions:   policy.Conditions,
	})
}

// ListPolicies handles GET /sys/policies.
func (h *PolicyHandler) ListPolicies(c *gin.Context) {
	policies, err := h.svc.ListPolicies(c.Request.Context())
	if err != nil {
		_ = c.Error(err)
		return
	}
	out := make([]dto.PolicyResponse, 0, len(policies))
	for _, policy := range policies {
		out = append(out, dto.PolicyResponse{
			Name:         policy.Name,
			Effect:       string(policy.Effect),
			Resources:    policy.Resources,
			Actions:      policy.Actions,
			Capabilities: policy.Capabilities,
			Includes:     policy.Includes,
			Conditions:   policy.Conditions,
		})
	}
	c.JSON(http.StatusOK, gin.H{"policies": out})
}

// DeletePolicy handles DELETE /sys/policies/:name.
func (h *PolicyHandler) DeletePolicy(c *gin.Context) {
	if err := h.svc.DeletePolicy(c.Request.Context(), c.Param("name")); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

// PutRole handles PUT /sys/roles/:name.
func (h *PolicyHandler) PutRole(c *gin.Context) {
	var req dto.RoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	role := &domainauth.Role{
		Name:                          c.Param("name"),
		Policies:                      req.Policies,
		PolicyGroups:                  req.PolicyGroups,
		BoundServiceAccountNames:      req.BoundServiceAccountNames,
		BoundServiceAccountNamespaces: req.BoundServiceAccountNamespaces,
		AuthMethod:                    req.AuthMethod,
		RequireMFA:                    req.RequireMFA,
	}
	if req.OIDC != nil {
		if !h.oidcEnabled {
			_ = c.Error(common.New(common.ErrCodeForbidden, "OIDC authentication is disabled (KNXVAULT_AUTH_OIDC_ENABLED=false)"))
			return
		}
		role.OIDC = &domainauth.OIDCConfig{
			Issuer:   req.OIDC.Issuer,
			Audience: req.OIDC.Audience,
			JWKSURL:  req.OIDC.JWKSURL,
			MaxTTL:   req.OIDC.MaxTTLSeconds,
		}
	}
	if err := h.svc.SaveRole(c.Request.Context(), role); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ListRoles handles GET /sys/roles.
func (h *PolicyHandler) ListRoles(c *gin.Context) {
	roles, err := h.svc.ListRoles(c.Request.Context())
	if err != nil {
		_ = c.Error(err)
		return
	}
	out := make([]dto.RoleResponse, 0, len(roles))
	for _, role := range roles {
		out = append(out, roleToDTO(role))
	}
	c.JSON(http.StatusOK, gin.H{"roles": out})
}

// DeleteRole handles DELETE /sys/roles/:name.
func (h *PolicyHandler) DeleteRole(c *gin.Context) {
	if err := h.svc.DeleteRole(c.Request.Context(), c.Param("name")); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

// GetRole handles GET /sys/roles/:name.
func (h *PolicyHandler) GetRole(c *gin.Context) {
	role, err := h.svc.GetRole(c.Request.Context(), c.Param("name"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, roleToDTO(role))
}

// ImportHCL handles POST /sys/policies/:name/import (W41-08).
func (h *PolicyHandler) ImportHCL(c *gin.Context) {
	var req dto.PolicyImportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	policies, err := auth.ImportHCLPolicy(c.Param("name"), req.HCL)
	if err != nil {
		_ = c.Error(err)
		return
	}
	for _, policy := range policies {
		p := policy
		if err := h.svc.SavePolicy(c.Request.Context(), &p); err != nil {
			_ = c.Error(err)
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"imported": len(policies)})
}

func roleToDTO(role *domainauth.Role) dto.RoleResponse {
	resp := dto.RoleResponse{
		Name:                          role.Name,
		Policies:                      role.Policies,
		PolicyGroups:                  role.PolicyGroups,
		BoundServiceAccountNames:      role.BoundServiceAccountNames,
		BoundServiceAccountNamespaces: role.BoundServiceAccountNamespaces,
		AuthMethod:                    role.AuthMethod,
		RequireMFA:                    role.RequireMFA,
	}
	if role.OIDC != nil {
		resp.OIDC = &dto.OIDCConfig{
			Issuer:        role.OIDC.Issuer,
			Audience:      role.OIDC.Audience,
			JWKSURL:       role.OIDC.JWKSURL,
			MaxTTLSeconds: role.OIDC.MaxTTL,
		}
	}
	return resp
}
