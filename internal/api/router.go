// Package api wires the HTTP API layer.
package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
)

// NewRouter builds the Gin engine with all routes registered.
func NewRouter(log *zap.Logger, version string, deps RouterDeps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.RequestID())
	r.Use(metrics.Middleware())
	r.Use(middleware.RequestLogger(log))
	r.Use(middleware.ErrorHandler())

	metrics.SetBuildInfo(version)
	r.GET("/metrics", metrics.Handler())

	health := handlers.NewHealthHandler(version, deps.Ready, deps.HAEnabled, deps.IsLeader)
	r.GET("/health", health.Live)
	r.GET("/ready", health.Ready)

	RegisterOpenAPIRoutes(r)

	if deps.AuthService != nil {
		authHandler := handlers.NewAuthHandler(deps.AuthService, deps.TokenTTL)
		authGroup := r.Group("/auth")
		{
			authGroup.POST("/kubernetes", authHandler.LoginKubernetes)
			authGroup.POST("/token", authHandler.LoginToken)
		}
	}

	secured := r.Group("/")
	if deps.AuthService != nil {
		secured.Use(middleware.Auth(deps.AuthService))
	}

	if deps.AuthService != nil {
		sys := handlers.NewSysHandler(deps.AuthService)
		secured.GET("/sys/capabilities", sys.Capabilities)
	}

	if deps.PKIService != nil && deps.AuthService != nil {
		pkiHandler := handlers.NewPKIHandler(deps.PKIService)
		pkiGroup := secured.Group("/pki")
		pkiGroup.Use(middleware.RequirePermission(deps.AuthService, "pki", "write"))
		{
			pkiGroup.POST("/root", pkiHandler.CreateRoot)
			pkiGroup.POST("/intermediate", pkiHandler.CreateIntermediate)
			pkiGroup.POST("/issue", pkiHandler.Issue)
			pkiGroup.POST("/revoke", pkiHandler.Revoke)
		}
		secured.GET("/pki/ca/:id", middleware.RequirePermission(deps.AuthService, "pki", "read"), pkiHandler.GetCA)
		secured.GET("/pki/crl/:id", middleware.RequirePermission(deps.AuthService, "pki", "read"), pkiHandler.CRL)
	}

	if deps.SecretsService != nil && deps.AuthService != nil {
		secretsHandler := handlers.NewSecretsHandler(deps.SecretsService)
		secured.POST("/secrets/kv/*path",
			middleware.RequirePermission(deps.AuthService, "secrets/kv", "write"),
			secretsHandler.Write,
		)
		secured.GET("/secrets/kv/*path",
			middleware.RequirePermission(deps.AuthService, "secrets/kv", "read"),
			secretsHandler.Read,
		)
		secured.DELETE("/secrets/kv/*path",
			middleware.RequirePermission(deps.AuthService, "secrets/kv", "write"),
			secretsHandler.Delete,
		)
	}

	if deps.DatabaseService != nil && deps.AuthService != nil {
		dbHandler := handlers.NewDatabaseHandler(deps.DatabaseService)
		dbGroup := secured.Group("/secrets/database")
		dbGroup.Use(middleware.RequirePermission(deps.AuthService, "secrets/database", "write"))
		{
			dbGroup.PUT("/roles/:name", dbHandler.PutRole)
			dbGroup.POST("/creds/:role", dbHandler.GenerateCreds)
			dbGroup.POST("/renew/:lease_id", dbHandler.Renew)
			dbGroup.PUT("/revoke/:lease_id", dbHandler.Revoke)
		}
		secured.GET("/secrets/database/roles/:name",
			middleware.RequirePermission(deps.AuthService, "secrets/database", "read"),
			dbHandler.GetRole,
		)
	}

	if deps.PolicyService != nil && deps.AuthService != nil {
		policyHandler := handlers.NewPolicyHandler(deps.PolicyService)
		policyGroup := secured.Group("/sys")
		policyGroup.Use(middleware.RequirePermission(deps.AuthService, "sys/policies", "write"))
		{
			policyGroup.PUT("/policies/:name", policyHandler.PutPolicy)
			policyGroup.DELETE("/policies/:name", policyHandler.DeletePolicy)
			policyGroup.PUT("/roles/:name", policyHandler.PutRole)
		}
		secured.GET("/sys/policies",
			middleware.RequirePermission(deps.AuthService, "sys/policies", "read"),
			policyHandler.ListPolicies,
		)
		secured.GET("/sys/policies/:name",
			middleware.RequirePermission(deps.AuthService, "sys/policies", "read"),
			policyHandler.GetPolicy,
		)
		secured.GET("/sys/roles/:name",
			middleware.RequirePermission(deps.AuthService, "sys/roles", "read"),
			policyHandler.GetRole,
		)
	}

	if deps.AuditExportService != nil && deps.AuthService != nil {
		auditHandler := handlers.NewAuditHandler(deps.AuditExportService)
		secured.GET("/audit/export",
			middleware.RequirePermission(deps.AuthService, "audit/export", "read"),
			auditHandler.Export,
		)
		secured.POST("/audit/verify",
			middleware.RequirePermission(deps.AuthService, "audit/verify", "read"),
			auditHandler.Verify,
		)
	}

	return r
}
