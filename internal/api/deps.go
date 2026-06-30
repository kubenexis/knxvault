package api

import (
	"time"

	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/service"
)

// RouterDeps groups handlers wired into the HTTP router.
type RouterDeps struct {
	Ready              ReadinessChecker
	AuthService        *auth.Service
	PKIService         *service.PKIService
	SecretsService     *service.SecretsService
	DatabaseService    *service.DatabaseService
	PolicyService      *service.PolicyService
	AuditExportService *service.AuditExportService
	InjectService      *service.InjectService
	TokenTTL           time.Duration
	RateLimiter        *middleware.RateLimiter
	RequestSigning     *middleware.RequestSigning
	HAEnabled          bool
	IsLeader           func() bool
}
