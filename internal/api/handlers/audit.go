package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/service"
)

// AuditHandler serves audit export and verification endpoints.
type AuditHandler struct {
	svc *service.AuditExportService
}

// NewAuditHandler constructs an AuditHandler.
func NewAuditHandler(svc *service.AuditExportService) *AuditHandler {
	return &AuditHandler{svc: svc}
}

// Export handles GET /audit/export.
func (h *AuditHandler) Export(c *gin.Context) {
	opts := repository.AuditListOptions{}
	if raw := c.Query("limit"); raw != "" {
		if limit, err := strconv.Atoi(raw); err == nil {
			opts.Limit = limit
		}
	}
	if raw := c.Query("offset"); raw != "" {
		if offset, err := strconv.Atoi(raw); err == nil {
			opts.Offset = offset
		}
	}
	if raw := c.Query("since"); raw != "" {
		if since, err := time.Parse(time.RFC3339, raw); err == nil {
			opts.Since = &since
		}
	}

	result, err := h.svc.Export(c.Request.Context(), opts)
	if err != nil {
		_ = c.Error(err)
		return
	}

	entries := make([]dto.AuditEntryResponse, 0, len(result.Entries))
	for _, entry := range result.Entries {
		entries = append(entries, dto.AuditEntryResponse{
			ID:             entry.ID,
			Timestamp:      entry.Timestamp,
			Actor:          entry.Actor,
			Action:         entry.Action,
			Resource:       entry.Resource,
			Status:         entry.Status,
			Details:        entry.Details,
			Hash:           entry.Hash,
			AuthMethod:     entry.AuthMethod,
			SourceIP:       entry.SourceIP,
			ClientIdentity: entry.ClientIdentity,
			FailureReason:  entry.FailureReason,
			RequestID:      entry.RequestID,
			Namespace:      entry.Namespace,
		})
	}
	c.JSON(http.StatusOK, dto.AuditExportResponse{
		Entries:   entries,
		HeadHash:  result.HeadHash,
		Signature: result.Signature,
		SignedAt:  result.SignedAt,
	})
}

// Verify handles POST /audit/verify.
func (h *AuditHandler) Verify(c *gin.Context) {
	var req dto.AuditVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	result, err := h.svc.Verify(c.Request.Context(), req.Signature, req.SignedAt)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.AuditVerifyResponse{
		Valid:     result.Valid,
		HeadHash:  result.HeadHash,
		Signature: result.Signature,
		Message:   result.Message,
	})
}
