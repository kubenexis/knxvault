// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/auth"
	databaseengine "github.com/kubenexis/knxvault/internal/engine/secrets/database"
	"github.com/kubenexis/knxvault/internal/service"
)

// DatabaseHandler serves dynamic database credential endpoints.
type DatabaseHandler struct {
	svc        *service.DatabaseService
	tenantMode bool
}

// NewDatabaseHandler constructs a DatabaseHandler.
func NewDatabaseHandler(svc *service.DatabaseService) *DatabaseHandler {
	return &DatabaseHandler{svc: svc}
}

// SetTenantMode enables lease ID tenant scoping (W64-01).
func (h *DatabaseHandler) SetTenantMode(enabled bool) {
	if h != nil {
		h.tenantMode = enabled
	}
}

// PutRole handles PUT /secrets/database/roles/:name.
func (h *DatabaseHandler) PutRole(c *gin.Context) {
	name := c.Param("name")
	var req dto.DatabaseRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	cfg := databaseengine.RoleConfig{
		Name:                 name,
		TTLSeconds:           req.TTLSeconds,
		DefaultTTL:           req.DefaultTTL,
		MaxTTL:               req.MaxTTL,
		Period:               req.Period,
		Renewable:            req.Renewable,
		MaxLeases:            req.MaxLeases,
		UsernamePrefix:       req.UsernamePrefix,
		DefaultUsername:      req.DefaultUsername,
		CreationStatements:   req.CreationStatements,
		RevocationStatements: req.RevocationStatements,
		ExecutionMode:        req.ExecutionMode,
		AdminCredentialsPath: req.AdminCredentialsPath,
		Config:               req.Config,
	}
	if err := h.svc.SaveRole(c.Request.Context(), cfg); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

// GetRole handles GET /secrets/database/roles/:name.
func (h *DatabaseHandler) GetRole(c *gin.Context) {
	role, err := h.svc.GetRole(c.Request.Context(), c.Param("name"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.DatabaseRoleResponse{
		Name:                 role.Name,
		TTLSeconds:           role.TTLSeconds,
		DefaultTTL:           role.DefaultTTL,
		MaxTTL:               role.MaxTTL,
		Period:               role.Period,
		Renewable:            role.Renewable,
		MaxLeases:            role.MaxLeases,
		UsernamePrefix:       role.UsernamePrefix,
		DefaultUsername:      role.DefaultUsername,
		CreationStatements:   role.CreationStatements,
		RevocationStatements: role.RevocationStatements,
		ExecutionMode:        role.ExecutionMode,
		AdminCredentialsPath: role.AdminCredentialsPath,
		Config:               role.Config,
	})
}

// GenerateCreds handles POST /secrets/database/creds/:role.
func (h *DatabaseHandler) GenerateCreds(c *gin.Context) {
	var req dto.DatabaseCredsRequest
	_ = c.ShouldBindJSON(&req)
	ns := ""
	if rc, ok := auth.RequestContextFromContext(c.Request.Context()); ok {
		ns = rc.Namespace
	}
	result, err := h.svc.GenerateCredentials(c.Request.Context(), databaseengine.CredsRequest{
		Role:       c.Param("role"),
		TTLSecond:  req.TTLSeconds,
		TokenID:    middleware.TokenID(c),
		Tenant:     ns,
		TenantMode: h.tenantMode,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, toDatabaseCredsResponse(result))
}

// Renew handles POST /secrets/database/renew/:lease_id.
func (h *DatabaseHandler) Renew(c *gin.Context) {
	var req dto.DatabaseRenewRequest
	_ = c.ShouldBindJSON(&req)
	result, err := h.svc.Renew(c.Request.Context(), c.Param("lease_id"), req.TTLSeconds)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, toDatabaseCredsResponse(result))
}

func toDatabaseCredsResponse(result *databaseengine.CredsResult) dto.DatabaseCredsResponse {
	return dto.DatabaseCredsResponse{
		LeaseFields: dto.NewLeaseFields(result.LeaseID, result.TTLSeconds, result.MaxTTL, result.ExpiresAt, result.Warnings),
		Username:    result.Username,
		Password:    result.Password,
		Role:        result.Role,
		TTLSeconds:  result.TTLSeconds,
		Statements:  result.Statements,
	}
}

// Revoke handles PUT /secrets/database/revoke/:lease_id.
func (h *DatabaseHandler) Revoke(c *gin.Context) {
	result, err := h.svc.Revoke(c.Request.Context(), c.Param("lease_id"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	if result != nil && len(result.RevocationStatements) > 0 {
		c.JSON(http.StatusOK, dto.DatabaseRevokeResponse{
			RevocationStatements: result.RevocationStatements,
		})
		return
	}
	c.Status(http.StatusNoContent)
}
