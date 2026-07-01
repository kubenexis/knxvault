package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	databaseengine "github.com/kubenexis/knxvault/internal/engine/secrets/database"
	"github.com/kubenexis/knxvault/internal/service"
)

// DatabaseHandler serves dynamic database credential endpoints.
type DatabaseHandler struct {
	svc *service.DatabaseService
}

// NewDatabaseHandler constructs a DatabaseHandler.
func NewDatabaseHandler(svc *service.DatabaseService) *DatabaseHandler {
	return &DatabaseHandler{svc: svc}
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
	result, err := h.svc.GenerateCredentials(c.Request.Context(), databaseengine.CredsRequest{
		Role:      c.Param("role"),
		TTLSecond: req.TTLSeconds,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.DatabaseCredsResponse{
		LeaseID:    result.LeaseID,
		Username:   result.Username,
		Password:   result.Password,
		Role:       result.Role,
		TTLSeconds: result.TTLSeconds,
		ExpiresAt:  result.ExpiresAt,
		Statements: result.Statements,
	})
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
	c.JSON(http.StatusOK, dto.DatabaseCredsResponse{
		LeaseID:    result.LeaseID,
		Username:   result.Username,
		Password:   result.Password,
		Role:       result.Role,
		TTLSeconds: result.TTLSeconds,
		ExpiresAt:  result.ExpiresAt,
		Statements: result.Statements,
	})
}

// Revoke handles PUT /secrets/database/revoke/:lease_id.
func (h *DatabaseHandler) Revoke(c *gin.Context) {
	result, err := h.svc.Revoke(c.Request.Context(), c.Param("lease_id"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.DatabaseRevokeResponse{
		LeaseID:              result.LeaseID,
		RevocationStatements: result.RevocationStatements,
	})
}
