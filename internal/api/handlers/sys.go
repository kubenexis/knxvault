package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	"github.com/kubenexis/knxvault/internal/notify"
	"github.com/kubenexis/knxvault/internal/service"
	"github.com/kubenexis/knxvault/internal/sys"
)

// SealController controls operational seal state.
type SealController interface {
	Sealed() bool
	Seal()
	Unseal(key []byte) bool
}

// RaftMembership controls cluster membership changes.
type RaftMembership interface {
	AddNode(ctx context.Context, nodeID uint64, address string) error
	RemoveNode(ctx context.Context, nodeID uint64) error
}

// SysHandler serves system endpoints.
type SysHandler struct {
	auth            *auth.Service
	pki             *service.PKIService
	database        *service.DatabaseService
	rotation        *service.RotationService
	masterKey       *service.MasterKeyService
	seal            SealController
	raft            RaftMembership
	masterKeyBytes  []byte
	exposureAuto    bool
	exposureWebhook *notify.Webhook
}

// NewSysHandler constructs a SysHandler.
func NewSysHandler(
	svc *auth.Service,
	pki *service.PKIService,
	database *service.DatabaseService,
	rotation *service.RotationService,
	masterKey *service.MasterKeyService,
	seal SealController,
	raft RaftMembership,
	masterKeyBytes []byte,
	exposureAuto bool,
	exposureWebhook *notify.Webhook,
) *SysHandler {
	return &SysHandler{
		auth:            svc,
		pki:             pki,
		database:        database,
		rotation:        rotation,
		masterKey:       masterKey,
		seal:            seal,
		raft:            raft,
		masterKeyBytes:  masterKeyBytes,
		exposureAuto:    exposureAuto,
		exposureWebhook: exposureWebhook,
	}
}

// Capabilities handles GET /sys/capabilities.
func (h *SysHandler) Capabilities(c *gin.Context) {
	principal, ok := auth.PrincipalFromContext(c.Request.Context())
	if !ok || h.auth == nil {
		c.JSON(http.StatusOK, dto.CapabilitiesResponse{Capabilities: []string{}})
		return
	}

	c.JSON(http.StatusOK, dto.CapabilitiesResponse{
		Capabilities: h.auth.Capabilities(principal),
	})
}

// Init handles POST /sys/init one-time bootstrap.
func (h *SysHandler) Init(c *gin.Context) {
	var req dto.InitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	fp := ""
	if len(h.masterKeyBytes) > 0 {
		sum := sha256.Sum256(h.masterKeyBytes)
		fp = hex.EncodeToString(sum[:8])
	}
	if err := sys.MarkInitialized(fp); err != nil {
		_ = c.Error(common.Wrap(common.ErrCodeValidation, err.Error(), err))
		return
	}
	var caResp *dto.CAResponse
	if req.CreateRootCA && h.pki != nil {
		name := req.RootCAName
		if name == "" {
			name = "root"
		}
		cn := req.RootCommonName
		if cn == "" {
			cn = "KNXVault Root CA"
		}
		result, err := h.pki.CreateRoot(c.Request.Context(), pkiengine.CreateRootRequest{
			Name:       name,
			CommonName: cn,
			TTL:        "87600h",
		})
		if err != nil {
			_ = c.Error(err)
			return
		}
		caResp = &dto.CAResponse{
			ID:        result.ID.String(),
			Name:      result.Name,
			CertPEM:   result.CertPEM,
			Serial:    result.Serial,
			ExpiresAt: result.ExpiresAt.Format(time.RFC3339),
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"initialized":            true,
		"master_key_fingerprint": fp,
		"root_ca":                caResp,
	})
}

// ReportExposure handles POST /sys/exposure/report.
func (h *SysHandler) ReportExposure(c *gin.Context) {
	var req dto.ExposureReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	actions := make([]string, 0, 2)
	if h.exposureAuto {
		if req.LeaseID != "" && h.database != nil {
			if err := h.database.Revoke(c.Request.Context(), req.LeaseID); err == nil {
				actions = append(actions, "lease_revoked")
			}
		}
		if req.SecretPath != "" && h.rotation != nil {
			policy, err := h.rotation.GetPolicy(c.Request.Context(), req.SecretPath)
			if err == nil && policy != nil {
				if err := h.rotation.RotatePath(c.Request.Context(), policy); err == nil {
					actions = append(actions, "kv_rotated")
				}
			}
		}
	}
	if h.exposureWebhook != nil {
		_ = h.exposureWebhook.Send(c.Request.Context(), notify.Event{
			Event:    "exposure.reported",
			Path:     req.SecretPath,
			LeaseID:  req.LeaseID,
			Severity: req.Severity,
			Detector: req.Detector,
			Details: map[string]any{
				"fingerprint": req.Fingerprint,
				"actions":     actions,
			},
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"reported": true,
		"actions":  actions,
	})
}

// RotateMasterKey handles POST /sys/rotate-master-key.
func (h *SysHandler) RotateMasterKey(c *gin.Context) {
	if h.masterKey == nil {
		_ = c.Error(common.New(common.ErrCodeInternal, "master key rotation not configured"))
		return
	}
	var req dto.RotateMasterKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	result, err := h.masterKey.Rotate(c.Request.Context(), service.RotateRequest{NewKeyBase64: req.NewKey})
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.RotateMasterKeyResponse{KeyVersion: int(result.KeyVersion)})
}

// Seal handles POST /sys/seal.
func (h *SysHandler) Seal(c *gin.Context) {
	if h.seal == nil {
		_ = c.Error(common.New(common.ErrCodeInternal, "seal not configured"))
		return
	}
	h.seal.Seal()
	c.JSON(http.StatusOK, gin.H{"sealed": true})
}

// Unseal handles POST /sys/unseal.
func (h *SysHandler) Unseal(c *gin.Context) {
	if h.seal == nil {
		_ = c.Error(common.New(common.ErrCodeInternal, "seal not configured"))
		return
	}
	var req dto.UnsealRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.Key)
	if err != nil {
		_ = c.Error(common.Wrap(common.ErrCodeValidation, "invalid base64 unseal key", err))
		return
	}
	if !h.seal.Unseal(raw) {
		_ = c.Error(common.New(common.ErrCodeValidation, "invalid unseal key"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"sealed": false})
}

// RaftAddNode handles POST /sys/raft/add-node.
func (h *SysHandler) RaftAddNode(c *gin.Context) {
	if h.raft == nil {
		_ = c.Error(common.New(common.ErrCodeInternal, "raft membership not configured"))
		return
	}
	var req dto.RaftAddNodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	if err := h.raft.AddNode(c.Request.Context(), req.NodeID, req.Address); err != nil {
		_ = c.Error(common.Wrap(common.ErrCodeInternal, "add raft node", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"added": true, "node_id": req.NodeID})
}

// RaftRemoveNode handles POST /sys/raft/remove-node.
func (h *SysHandler) RaftRemoveNode(c *gin.Context) {
	if h.raft == nil {
		_ = c.Error(common.New(common.ErrCodeInternal, "raft membership not configured"))
		return
	}
	var req dto.RaftRemoveNodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(err)
		return
	}
	if err := h.raft.RemoveNode(c.Request.Context(), req.NodeID); err != nil {
		_ = c.Error(common.Wrap(common.ErrCodeInternal, "remove raft node", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"removed": true, "node_id": req.NodeID})
}

// IssueListenerTLS is a placeholder for automatic listener certificate issuance.
func (h *SysHandler) IssueListenerTLS(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, dto.ErrorResponse{
		ErrorCode: "not_implemented",
		Message:   "automatic listener TLS issuance is not yet implemented",
		Timestamp: time.Now().UTC(),
	})
}
