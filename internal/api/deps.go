// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"time"

	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/auth"
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
	LeaseService         *service.LeaseService
	AuditPackService     *service.AuditPackService
	MachineIdentitySvc   *service.MachineIdentityService
	CubbyholeService     *service.CubbyholeService
	WrappingService      *service.WrappingService
	TransitService       *service.TransitService
	IdentityService      *service.IdentityService
	TenantMode           bool
	AuthzAudit           *middleware.AuthzAudit
	ExposureSigningKey   string
	ExposureAutoRevoke   bool
	ExposurePathPrefixes []string
	ExposureWebhook      *notify.Webhook
	MTLSRequired         bool
	TokenTTL             time.Duration
	RateLimiter          *middleware.RateLimiter
	SharedRateLimiter    *middleware.SharedRateLimiter
	AuthLoginLimiter     *middleware.RateLimiter
	TokenCreateLimiter   *middleware.RateLimiter
	RequestSigning       *middleware.RequestSigning
	HAStatus             handlers.HAStatusProvider
	IsLeader             func() bool
	// TrustedProxies configures Gin X-Forwarded-For trust (W50-18). nil/empty = trust none.
	TrustedProxies []string
	// MetricsBearerToken when set authenticates GET /metrics (W50-19).
	MetricsBearerToken string
	// MetricsDedicatedOnly when true omits /metrics from the API router (W75-03 dedicated listener).
	// Zero value (false) keeps the lab/test default: GET /metrics on the main HTTP listener.
	MetricsDedicatedOnly bool
	// UnsealAllowCIDRs restricts POST /sys/unseal clients (empty = allow all).
	UnsealAllowCIDRs []string
}
