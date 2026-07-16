package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/backup"
	"github.com/kubenexis/knxvault/internal/domain/common"
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
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		_ = c.Error(common.Wrap(common.ErrCodeValidation, "read body", err))
		return
	}
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			_ = c.Error(common.Wrap(common.ErrCodeValidation, "invalid backup request json", err))
			return
		}
	}

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
