package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/service"
)

// PolicyHandler serves RBAC policy and role endpoints.
type PolicyHandler struct {
	svc *service.PolicyService
}

// NewPolicyHandler constructs a PolicyHandler.
func NewPolicyHandler(svc *service.PolicyService) *PolicyHandler {
	return &PolicyHandler{svc: svc}
}

// PutPolicy handles PUT /sys/policies/:name.
func (h *PolicyHandler) PutPolicy(c *gin.Context) {
	var req dto.PolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	policy := &domainauth.Policy{
		Name:       c.Param("name"),
		Effect:     domainauth.Effect(req.Effect),
		Resources:  req.Resources,
		Actions:    req.Actions,
		Conditions: req.Conditions,
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
		Name:       policy.Name,
		Effect:     string(policy.Effect),
		Resources:  policy.Resources,
		Actions:    policy.Actions,
		Conditions: policy.Conditions,
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
			Name:       policy.Name,
			Effect:     string(policy.Effect),
			Resources:  policy.Resources,
			Actions:    policy.Actions,
			Conditions: policy.Conditions,
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
		BoundServiceAccountNames:      req.BoundServiceAccountNames,
		BoundServiceAccountNamespaces: req.BoundServiceAccountNamespaces,
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
		out = append(out, dto.RoleResponse{
			Name:                          role.Name,
			Policies:                      role.Policies,
			BoundServiceAccountNames:      role.BoundServiceAccountNames,
			BoundServiceAccountNamespaces: role.BoundServiceAccountNamespaces,
		})
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
	c.JSON(http.StatusOK, dto.RoleResponse{
		Name:                          role.Name,
		Policies:                      role.Policies,
		BoundServiceAccountNames:      role.BoundServiceAccountNames,
		BoundServiceAccountNamespaces: role.BoundServiceAccountNamespaces,
	})
}
