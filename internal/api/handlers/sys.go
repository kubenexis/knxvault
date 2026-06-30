package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	"github.com/kubenexis/knxvault/internal/service"
	"github.com/kubenexis/knxvault/internal/sys"
)

// SysHandler serves system endpoints.
type SysHandler struct {
	auth       *auth.Service
	pki        *service.PKIService
	masterKey  []byte
}

// NewSysHandler constructs a SysHandler.
func NewSysHandler(svc *auth.Service, pki *service.PKIService, masterKey []byte) *SysHandler {
	return &SysHandler{auth: svc, pki: pki, masterKey: masterKey}
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
	if len(h.masterKey) > 0 {
		sum := sha256.Sum256(h.masterKey)
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

// IssueListenerTLS is a placeholder for automatic listener certificate issuance.
func (h *SysHandler) IssueListenerTLS(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, dto.ErrorResponse{
		ErrorCode: "not_implemented",
		Message:   "automatic listener TLS issuance is not yet implemented",
		Timestamp: time.Now().UTC(),
	})
}