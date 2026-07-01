package api

import (
	"time"

	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/crypto/openssl"
	"github.com/kubenexis/knxvault/internal/notify"
	"github.com/kubenexis/knxvault/internal/service"
)

// RouterDeps groups handlers wired into the HTTP router.
type RouterDeps struct {
	Ready                ReadinessChecker
	Seal                 handlers.SealController
	MasterKey            []byte
	MasterKeyService     *service.MasterKeyService
	RaftMembership       handlers.RaftMembership
	CORSAllowedOrigins   []string
	AuthService          *auth.Service
	OpenSSL              *openssl.Wrapper
	PKIService           *service.PKIService
	SecretsService       *service.SecretsService
	DatabaseService      *service.DatabaseService
	SSHService           *service.SSHService
	PolicyService        *service.PolicyService
	AuditExportService   *service.AuditExportService
	InjectService        *service.InjectService
	BackupService        *service.BackupService
	RotationService      *service.RotationService
	OrchestrationService *service.OrchestrationService
	MachineIdentitySvc   *service.MachineIdentityService
	ExposureSigningKey   string
	ExposureAutoRevoke   bool
	ExposureWebhook      *notify.Webhook
	MTLSRequired         bool
	TokenTTL             time.Duration
	RateLimiter          *middleware.RateLimiter
	RequestSigning       *middleware.RequestSigning
	HAStatus             handlers.HAStatusProvider
	IsLeader             func() bool
}
