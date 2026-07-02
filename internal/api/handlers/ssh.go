package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	sshengine "github.com/kubenexis/knxvault/internal/engine/secrets/ssh"
	"github.com/kubenexis/knxvault/internal/service"
)

// SSHHandler serves dynamic OpenSSH credential endpoints.
type SSHHandler struct {
	svc *service.SSHService
}

// NewSSHHandler constructs an SSHHandler.
func NewSSHHandler(svc *service.SSHService) *SSHHandler {
	return &SSHHandler{svc: svc}
}

// PutRole handles PUT /secrets/ssh/roles/:name.
func (h *SSHHandler) PutRole(c *gin.Context) {
	name := c.Param("name")
	var req dto.SSHRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	cfg := sshengine.RoleConfig{
		Name:         name,
		TTLSeconds:   req.TTLSeconds,
		DefaultTTL:   req.DefaultTTL,
		MaxTTL:       req.MaxTTL,
		Period:       req.Period,
		Renewable:    req.Renewable,
		MaxLeases:    req.MaxLeases,
		CAKeyPath:    req.CAKeyPath,
		AllowedUsers: req.AllowedUsers,
		DefaultUser:  req.DefaultUser,
		KeyType:      req.KeyType,
		Extensions:   req.Extensions,
	}
	if err := h.svc.SaveRole(c.Request.Context(), cfg); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

// GetRole handles GET /secrets/ssh/roles/:name.
func (h *SSHHandler) GetRole(c *gin.Context) {
	role, err := h.svc.GetRole(c.Request.Context(), c.Param("name"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.SSHRoleResponse{
		Name:         role.Name,
		TTLSeconds:   role.TTLSeconds,
		DefaultTTL:   role.DefaultTTL,
		MaxTTL:       role.MaxTTL,
		Period:       role.Period,
		Renewable:    role.Renewable,
		MaxLeases:    role.MaxLeases,
		CAKeyPath:    role.CAKeyPath,
		AllowedUsers: role.AllowedUsers,
		DefaultUser:  role.DefaultUser,
		KeyType:      role.KeyType,
		Extensions:   role.Extensions,
	})
}

// GenerateCreds handles POST /secrets/ssh/creds/:role.
func (h *SSHHandler) GenerateCreds(c *gin.Context) {
	var req dto.SSHCredsRequest
	_ = c.ShouldBindJSON(&req)
	result, err := h.svc.GenerateCredentials(c.Request.Context(), sshengine.CredsRequest{
		Role:      c.Param("role"),
		Username:  req.Username,
		TTLSecond: req.TTLSeconds,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, toSSHCredsResponse(result))
}

// Renew handles POST /secrets/ssh/renew/:lease_id.
func (h *SSHHandler) Renew(c *gin.Context) {
	var req dto.DatabaseRenewRequest
	_ = c.ShouldBindJSON(&req)
	result, err := h.svc.Renew(c.Request.Context(), c.Param("lease_id"), req.TTLSeconds)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, toSSHCredsResponse(result))
}

func toSSHCredsResponse(result *sshengine.CredsResult) dto.SSHCredsResponse {
	return dto.SSHCredsResponse{
		LeaseFields: dto.NewLeaseFields(result.LeaseID, result.TTLSeconds, result.MaxTTL, result.ExpiresAt, result.Warnings),
		Username:    result.Username,
		PrivateKey:  result.PrivateKey,
		SignedKey:   result.SignedKey,
		Role:        result.Role,
		TTLSeconds:  result.TTLSeconds,
	}
}

// Revoke handles PUT /secrets/ssh/revoke/:lease_id.
func (h *SSHHandler) Revoke(c *gin.Context) {
	if err := h.svc.Revoke(c.Request.Context(), c.Param("lease_id")); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}
