// Package api wires the HTTP API layer.
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/crypto/openssl"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
	buildinfo "github.com/kubenexis/knxvault/internal/version"
)

// NewRouter builds the Gin engine with all routes registered.
func NewRouter(log *zap.Logger, version string, tracingEnabled bool, deps RouterDeps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	if tracingEnabled {
		r.Use(otelgin.Middleware("knxvault"))
	}
	r.Use(middleware.RequestID())
	r.Use(middleware.SecurityHeaders(middleware.SecurityHeadersConfig{
		CORSAllowedOrigins: deps.CORSAllowedOrigins,
	}))
	r.Use(metrics.Middleware())
	r.Use(middleware.RequestLogger(log))
	r.Use(middleware.ErrorHandler())

	build := buildinfo.Get()
	metrics.SetBuildInfo(build.Version, build.Commit, build.BuildID)
	r.GET("/metrics", metrics.Handler())

	health := handlers.NewHealthHandler(version, deps.Ready, deps.HAStatus, deps.IsLeader)
	r.GET("/health", health.Live)
	r.GET("/ready", health.Ready)

	RegisterOpenAPIRoutes(r)

	if deps.AuthService != nil {
		authHandler := handlers.NewAuthHandler(deps.AuthService, deps.TokenTTL)
		authGroup := r.Group("/auth")
		{
			authGroup.POST("/kubernetes", authHandler.LoginKubernetes)
			authGroup.POST("/oidc/:role", authHandler.LoginOIDC)
			authGroup.POST("/token", authHandler.LoginToken)
		}
		securedAuth := authGroup.Group("/")
		securedAuth.Use(middleware.Auth(deps.AuthService))
		if deps.Seal != nil {
			securedAuth.Use(middleware.SealGuard(deps.Seal))
		}
		{
			securedAuth.POST("/token/create",
				middleware.RequirePermission(deps.AuthService, "sys/auth", "write"),
				authHandler.CreateToken,
			)
			securedAuth.POST("/token/renew", authHandler.RenewToken)
			securedAuth.DELETE("/token/self", authHandler.RevokeSelfToken)
		}
	}

	secured := r.Group("/")
	if deps.AuthService != nil {
		if deps.RequestSigning != nil {
			secured.Use(deps.RequestSigning.Middleware())
		}
		secured.Use(middleware.Auth(deps.AuthService))
		if deps.Seal != nil {
			secured.Use(middleware.SealGuard(deps.Seal))
		}
		if deps.RateLimiter != nil {
			secured.Use(deps.RateLimiter.Middleware())
		}
	}

	if deps.AuthService != nil {
		sys := handlers.NewSysHandler(
			deps.AuthService,
			deps.PKIService,
			deps.DatabaseService,
			deps.RotationService,
			deps.OrchestrationService,
			deps.MasterKeyService,
			deps.Seal,
			deps.RaftMembership,
			deps.MasterKey,
			deps.ExposureAutoRevoke,
			deps.ExposureWebhook,
		)
		secured.GET("/sys/capabilities", sys.Capabilities)
		secured.POST("/sys/init",
			middleware.RequirePermission(deps.AuthService, "sys/init", "write"),
			sys.Init,
		)
		secured.POST("/sys/tls/issue-listener",
			middleware.RequirePermission(deps.AuthService, "sys/tls", "write"),
			sys.IssueListenerTLS,
		)
		secured.POST("/sys/rotation/run",
			middleware.RequirePermission(deps.AuthService, "sys/rotate", "write"),
			sys.RunRotation,
		)
		secured.POST("/sys/rotate-master-key",
			middleware.RequirePermission(deps.AuthService, "sys/rotate", "write"),
			sys.RotateMasterKey,
		)
		secured.POST("/sys/seal",
			middleware.RequirePermission(deps.AuthService, "sys/seal", "write"),
			sys.Seal,
		)

		if deps.RaftMembership != nil {
			secured.POST("/sys/raft/add-node",
				middleware.RequirePermission(deps.AuthService, "sys/raft", "write"),
				sys.RaftAddNode,
			)
			secured.POST("/sys/raft/remove-node",
				middleware.RequirePermission(deps.AuthService, "sys/raft", "write"),
				sys.RaftRemoveNode,
			)
		}
	}

	if deps.AuthService != nil {
		vaultCompat := handlers.NewVaultCompatHandler(deps.AuthService, deps.PKIService, deps.TokenTTL)
		v1 := r.Group("/v1")
		v1.POST("/auth/kubernetes/login", vaultCompat.LoginKubernetes)
		v1Auth := v1.Group("/")
		v1Auth.Use(middleware.Auth(deps.AuthService))
		if deps.Seal != nil {
			v1Auth.Use(middleware.SealGuard(deps.Seal))
		}
		v1Auth.POST("/pki/sign/:role",
			middleware.RequirePermission(deps.AuthService, "pki", "write"),
			vaultCompat.SignPKI,
		)
	}

	if deps.PKIService != nil {
		pkiHandler := handlers.NewPKIHandler(deps.PKIService)
		r.POST("/pki/ocsp/:id", pkiHandler.OCSP)
		if deps.AuthService != nil {
			pkiGroup := secured.Group("/pki")
			pkiGroup.Use(middleware.RequirePermission(deps.AuthService, "pki", "write"))
			pkiGroup.Use(openSSLBreakerMiddleware(deps.OpenSSL))
			{
				pkiGroup.POST("/root", pkiHandler.CreateRoot)
				pkiGroup.POST("/intermediate", pkiHandler.CreateIntermediate)
				pkiGroup.POST("/issue", pkiHandler.Issue)
				pkiGroup.POST("/renew", pkiHandler.Renew)
				pkiGroup.POST("/revoke", pkiHandler.Revoke)
				pkiGroup.POST("/ca/import", pkiHandler.ImportCA)
				pkiGroup.POST("/ca/:id/rotate", pkiHandler.RotateCA)
			}
			secured.GET("/pki/ca/:id", middleware.RequirePermission(deps.AuthService, "pki", "read"), pkiHandler.GetCA)
			secured.GET("/pki/ca/:id/export", middleware.RequirePermission(deps.AuthService, "pki", "read"), pkiHandler.ExportCA)
			secured.GET("/pki/crl/:id", middleware.RequirePermission(deps.AuthService, "pki", "read"), pkiHandler.CRL)
		}
	}

	if deps.SecretsService != nil && deps.AuthService != nil {
		secretsHandler := handlers.NewSecretsHandler(deps.SecretsService, deps.RotationService)
		kvWrite := secured.Group("/secrets/kv")
		if deps.MTLSRequired {
			kvWrite.Use(middleware.MTLSRequired(true))
		}
		kvWrite.POST("/*path",
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

	if deps.RotationService != nil && deps.AuthService != nil {
		secretsHandler := handlers.NewSecretsHandler(deps.SecretsService, deps.RotationService)
		secured.PUT("/sys/kv-rotation",
			middleware.RequirePermission(deps.AuthService, "secrets/kv", "write"),
			secretsHandler.PutRotation,
		)
		secured.DELETE("/sys/kv-rotation",
			middleware.RequirePermission(deps.AuthService, "secrets/kv", "write"),
			secretsHandler.DeleteRotation,
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

	if deps.InjectService != nil && deps.AuthService != nil {
		injectHandler := handlers.NewInjectHandler(deps.InjectService)
		secured.POST("/inject/render",
			middleware.RequirePermission(deps.AuthService, "inject/render", "read"),
			injectHandler.Render,
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

	if deps.MachineIdentitySvc != nil && deps.AuthService != nil {
		nhi := handlers.NewMachineIdentityHandler(deps.MachineIdentitySvc)
		secured.GET("/sys/machine-identities",
			middleware.RequirePermission(deps.AuthService, "sys/policies", "read"),
			nhi.List,
		)
		secured.DELETE("/sys/machine-identities/:id",
			middleware.RequirePermission(deps.AuthService, "sys/policies", "write"),
			nhi.Revoke,
		)
	}

	if deps.Seal != nil {
		sysUnseal := handlers.NewSysHandler(
			deps.AuthService, deps.PKIService, deps.DatabaseService, deps.RotationService,
			deps.OrchestrationService, deps.MasterKeyService, deps.Seal, deps.RaftMembership, deps.MasterKey,
			deps.ExposureAutoRevoke, deps.ExposureWebhook,
		)
		unsealLimiter := middleware.NewRateLimiter(10, true)
		r.POST("/sys/unseal", unsealLimiter.Middleware(), sysUnseal.Unseal)
	}

	if deps.ExposureSigningKey != "" {
		exposureSigning := middleware.NewExposureSigning(deps.ExposureSigningKey)
		r.POST("/sys/exposure/report", exposureSigning.Middleware(), func(c *gin.Context) {
			if deps.AuthService == nil {
				c.JSON(http.StatusServiceUnavailable, gin.H{"message": "not configured"})
				return
			}
			sysHandler := handlers.NewSysHandler(
				deps.AuthService, deps.PKIService, deps.DatabaseService, deps.RotationService,
				deps.OrchestrationService, deps.MasterKeyService, deps.Seal, deps.RaftMembership, deps.MasterKey,
				deps.ExposureAutoRevoke, deps.ExposureWebhook,
			)
			sysHandler.ReportExposure(c)
		})
	}

	if deps.BackupService != nil && deps.AuthService != nil {
		backupHandler := handlers.NewBackupHandler(deps.BackupService)
		sysBackup := secured.Group("/sys")
		sysBackup.Use(middleware.RequirePermission(deps.AuthService, "sys/backup", "write"))
		{
			sysBackup.POST("/backup", backupHandler.Create)
			sysBackup.POST("/restore", backupHandler.Restore)
		}
	}

	return r
}

func openSSLBreakerMiddleware(ossl *openssl.Wrapper) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ossl != nil && ossl.BreakerOpen() {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error_code": string(common.ErrCodeInternal),
				"message":    "openssl circuit breaker open",
			})
			return
		}
		c.Next()
	}
}
