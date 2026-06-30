package api

import (
	"time"

	"github.com/kubenexis/knxvault/internal/api/handlers"
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
	BackupService      *service.BackupService
	TokenTTL           time.Duration
	RateLimiter        *middleware.RateLimiter
	RequestSigning     *middleware.RequestSigning
	HAStatus           handlers.HAStatusProvider
	IsLeader           func() bool
}
