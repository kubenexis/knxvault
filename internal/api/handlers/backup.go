package handlers

import (
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/backup"
	"github.com/kubenexis/knxvault/internal/service"
)

// MaxBackupRestoreBytes limits POST /sys/restore payload size.
const MaxBackupRestoreBytes = 64 << 20 // 64 MiB

// BackupHandler serves backup and restore endpoints.
type BackupHandler struct {
	svc *service.BackupService
}

// NewBackupHandler constructs a BackupHandler.
func NewBackupHandler(svc *service.BackupService) *BackupHandler {
	return &BackupHandler{svc: svc}
}

// Create handles POST /sys/backup.
func (h *BackupHandler) Create(c *gin.Context) {
	var req dto.BackupCreateRequest
	_ = c.ShouldBindJSON(&req)

	data, err := h.svc.Create(c.Request.Context(), backup.ExportOptions{
		IncludeAudit: req.IncludeAudit,
		AuditLimit:   req.AuditLimit,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.BackupCreateResponse{
		Format: "knxvault-backup",
		Data:   base64.StdEncoding.EncodeToString(data),
	})
}

// Restore handles POST /sys/restore.
func (h *BackupHandler) Restore(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxBackupRestoreBytes)
	body, err := c.GetRawData()
	if err != nil {
		_ = c.Error(err)
		return
	}
	if len(body) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "backup payload required"})
		return
	}
	if err := h.svc.Restore(c.Request.Context(), body); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}
