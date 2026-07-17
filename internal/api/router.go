// Package api wires the HTTP API layer.
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
	buildinfo "github.com/kubenexis/knxvault/internal/version"
)

// NewRouter builds the Gin engine with all routes registered.
func NewRouter(log *zap.Logger, version string, tracingEnabled bool, deps RouterDeps) *gin.Engine {
	r := gin.New()
	// W50-18: do not trust X-Forwarded-For unless operators configure TrustedProxies.
	if len(deps.TrustedProxies) > 0 {
		_ = r.SetTrustedProxies(deps.TrustedProxies)
	} else {
		_ = r.SetTrustedProxies(nil)
	}
	r.Use(gin.Recovery())
	if tracingEnabled {
		r.Use(otelgin.Middleware("knxvault"))
	}
	r.Use(middleware.RequestID())
	r.Use(middleware.EnvironmentHeader())
	r.Use(middleware.SecurityHeaders(middleware.SecurityHeadersConfig{
		CORSAllowedOrigins: deps.CORSAllowedOrigins,
	}))
	r.Use(metrics.Middleware())
	r.Use(middleware.RequestLogger(log))
	r.Use(middleware.ErrorHandler())

	build := buildinfo.Get()
	metrics.SetBuildInfo(build.Version, build.Commit, build.BuildID)
	r.GET("/metrics", metrics.HandlerWithAuth(deps.MetricsBearerToken))

	health := handlers.NewHealthHandler(version, deps.Ready, deps.HAStatus, deps.IsLeader)
	r.GET("/health", health.Live)
	r.GET("/ready", health.Ready)

	RegisterOpenAPIRoutes(r)

	if deps.AuthService != nil {
		authHandler := handlers.NewAuthHandler(deps.AuthService, deps.TokenTTL)
		authGroup := r.Group("/auth")
		if deps.AuthLoginLimiter != nil {
			authGroup.Use(middleware.AuthLoginThrottle(deps.AuthLoginLimiter))
		}
		{
			authGroup.POST("/kubernetes", authHandler.LoginKubernetes)
			authGroup.POST("/oidc/:role", authHandler.LoginOIDC)
			authGroup.POST("/token", authHandler.LoginToken)
			authGroup.POST("/cert", authHandler.LoginCert) // mTLS client cert → token
			authGroup.POST("/ldap", authHandler.LoginLDAP) // W70 native LDAP
		}
		securedAuth := authGroup.Group("/")
		securedAuth.Use(middleware.Auth(deps.AuthService))
		if deps.Seal != nil {
			securedAuth.Use(middleware.SealGuard(deps.Seal))
		}
		{
			tokenCreate := []gin.HandlerFunc{
				middleware.RequirePermission(deps.AuthService, "sys/auth", "sudo"),
				authHandler.CreateToken,
			}
			if deps.TokenCreateLimiter != nil {
				tokenCreate = append([]gin.HandlerFunc{middleware.TokenCreateThrottle(deps.TokenCreateLimiter)}, tokenCreate...)
			}
			securedAuth.POST("/token/create", tokenCreate...)
			securedAuth.POST("/token/renew", authHandler.RenewToken)
			securedAuth.DELETE("/token/self", authHandler.RevokeSelfToken)
			delegateHandlers := []gin.HandlerFunc{
				middleware.RequirePermission(deps.AuthService, "auth/agent", "write"),
				authHandler.DelegateAgent,
			}
			if deps.TokenCreateLimiter != nil {
				delegateHandlers = append([]gin.HandlerFunc{middleware.TokenCreateThrottle(deps.TokenCreateLimiter)}, delegateHandlers...)
			}
			securedAuth.POST("/agent/delegate", delegateHandlers...)
		}
	}

	secured := r.Group("/")
	if deps.AuthService != nil {
		if deps.RequestSigning != nil {
			secured.Use(deps.RequestSigning.Middleware())
		}
		secured.Use(middleware.Auth(deps.AuthService))
		if deps.TenantMode {
			secured.Use(middleware.TenantEnforcement(true))
		}
		if deps.Seal != nil {
			secured.Use(middleware.SealGuard(deps.Seal))
		}
		if deps.SharedRateLimiter != nil {
			secured.Use(deps.SharedRateLimiter.Middleware())
		} else if deps.RateLimiter != nil {
			secured.Use(deps.RateLimiter.Middleware())
		}
	}

	if deps.AuthService != nil {
		authHandler := handlers.NewAuthHandler(deps.AuthService, deps.TokenTTL)
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
		secured.DELETE("/sys/auth/lockout",
			middleware.RequirePermission(deps.AuthService, "sys/auth", "sudo"),
			authHandler.ClearLockout,
		)
		// AppRole credential registration for cert-manager vault.auth.appRole
		vaultAppRole := handlers.NewVaultCompatHandler(deps.AuthService, deps.PKIService, deps.TokenTTL)
		secured.POST("/sys/auth/approle",
			middleware.RequirePermission(deps.AuthService, "sys/auth", "sudo"),
			vaultAppRole.RegisterAppRole,
		)
		secured.POST("/sys/rotate-master-key",
			middleware.RequirePermission(deps.AuthService, "sys/rotate", "write"),
			sys.RotateMasterKey,
		)
		secured.POST("/sys/seal",
			middleware.RequirePermission(deps.AuthService, "sys/seal", "write"),
			sys.Seal,
		)
		secured.POST("/sys/generate-unseal-shares",
			middleware.RequirePermission(deps.AuthService, "sys/seal", "write"),
			sys.GenerateUnsealShares,
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

	// Vault product profile (cert-manager Vault issuer): thin HTTP adapter over services.
	// See internal/compat/vault and docs/recipes/cert-manager-integration.md.
	if deps.AuthService != nil {
		vaultCompat := handlers.NewVaultCompatHandler(deps.AuthService, deps.PKIService, deps.TokenTTL).
			WithHealthProbe(deps.Seal, deps.HAStatus, version)
		v1 := r.Group("/v1")
		// Health is unauthenticated (Vault sys/health; cert-manager Ready probe).
		v1.GET("/sys/health", vaultCompat.SysHealth)
		if deps.AuthLoginLimiter != nil {
			v1.Use(middleware.AuthLoginThrottle(deps.AuthLoginLimiter))
		}
		// Explicit auth mounts (cert-manager defaults).
		v1.POST("/auth/kubernetes/login", vaultCompat.LoginKubernetes)
		v1.POST("/auth/approle/login", vaultCompat.LoginAppRole)
		// Custom auth mount paths (mountPath / path overrides).
		v1.POST("/auth/:mount/login", vaultCompat.LoginMount)

		v1Auth := v1.Group("/")
		v1Auth.Use(middleware.Auth(deps.AuthService))
		if deps.Seal != nil {
			v1Auth.Use(middleware.SealGuard(deps.Seal))
		}
		// Default PKI mount and custom mounts (Issuer.spec.vault.path = <mount>/sign/<role>).
		// W50-29: path-scoped capability pki|mount /sign/:role (falls back to pki write).
		v1Auth.POST("/pki/sign/:role",
			middleware.RequirePKISignCapability(deps.AuthService, "pki"),
			vaultCompat.SignPKI,
		)
		v1Auth.POST("/:mount/sign/:role",
			middleware.RequirePKISignCapability(deps.AuthService, ""),
			vaultCompat.SignPKI,
		)
	}

	if deps.PKIService != nil {
		pkiHandler := handlers.NewPKIHandler(deps.PKIService)
		// W52: rate-limit unauthenticated OCSP to reduce CA decrypt DoS.
		ocspLimiter := middleware.NewRateLimiter(120, true)
		r.POST("/pki/ocsp/:id", ocspLimiter.Middleware(), pkiHandler.OCSP)
		if deps.AuthService != nil {
			pkiGroup := secured.Group("/pki")
			pkiGroup.Use(middleware.RequirePermission(deps.AuthService, "pki", "write"))
			{
				pkiGroup.POST("/root", pkiHandler.CreateRoot)
				pkiGroup.POST("/intermediate", pkiHandler.CreateIntermediate)
				pkiGroup.POST("/issue", pkiHandler.Issue)
				pkiGroup.POST("/issue-client-cert", pkiHandler.IssueClientCert)
				pkiGroup.POST("/sign", pkiHandler.SignCSR)
				pkiGroup.POST("/renew", pkiHandler.Renew)
				pkiGroup.POST("/revoke", pkiHandler.Revoke)
				pkiGroup.POST("/ca/import", pkiHandler.ImportCA)
				pkiGroup.POST("/ca/:id/rotate",
					middleware.RequirePathCapability(deps.AuthService, "pki/ca", auth.CapWrite, "id", deps.AuthzAudit),
					pkiHandler.RotateCA,
				)
			}
			// by-name must register before :id so "by-name" is not parsed as a UUID id.
			secured.GET("/pki/ca/by-name/:name",
				middleware.RequirePermission(deps.AuthService, "pki", "read"),
				pkiHandler.GetCAByName,
			)
			secured.GET("/pki/ca/:id",
				middleware.RequirePathCapability(deps.AuthService, "pki/ca", auth.CapRead, "id", deps.AuthzAudit),
				pkiHandler.GetCA,
			)
			secured.GET("/pki/ca/:id/export",
				middleware.RequirePathCapability(deps.AuthService, "pki/ca", auth.CapRead, "id", deps.AuthzAudit),
				pkiHandler.ExportCA,
			)
			secured.GET("/pki/crl/:id",
				middleware.RequirePathCapability(deps.AuthService, "pki/crl", auth.CapRead, "id", deps.AuthzAudit),
				pkiHandler.CRL,
			)
		}
	}

	if deps.SecretsService != nil && deps.AuthService != nil {
		secretsHandler := handlers.NewSecretsHandler(deps.SecretsService, deps.RotationService, deps.AuthService)
		kvReadChain := []gin.HandlerFunc{
			middleware.EnrichKVResourceLabels(deps.SecretsService),
			middleware.RequireKVAccess(deps.AuthService, "", deps.AuthzAudit),
		}
		kvWriteChain := []gin.HandlerFunc{
			middleware.EnrichKVResourceLabels(deps.SecretsService),
			middleware.RequireKVAccess(deps.AuthService, auth.CapWrite, deps.AuthzAudit),
		}
		kvDeleteChain := []gin.HandlerFunc{
			middleware.EnrichKVResourceLabels(deps.SecretsService),
			middleware.RequireKVAccess(deps.AuthService, auth.CapDelete, deps.AuthzAudit),
		}
		kvWrite := secured.Group("/secrets/kv")
		if deps.MTLSRequired {
			kvWrite.Use(middleware.MTLSRequired(true))
		}
		kvWrite.POST("/*path", append(kvWriteChain, secretsHandler.Write)...)
		secured.GET("/secrets/kv/*path", append(kvReadChain, secretsHandler.Read)...)
		secured.DELETE("/secrets/kv/*path", append(kvDeleteChain, secretsHandler.Delete)...)
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

	if deps.SSHService != nil && deps.AuthService != nil {
		sshHandler := handlers.NewSSHHandler(deps.SSHService)
		sshGroup := secured.Group("/secrets/ssh")
		sshGroup.Use(middleware.RequirePermission(deps.AuthService, "secrets/ssh", "write"))
		{
			sshGroup.PUT("/roles/:name", sshHandler.PutRole)
			sshGroup.POST("/creds/:role", sshHandler.GenerateCreds)
			sshGroup.POST("/renew/:lease_id", sshHandler.Renew)
			sshGroup.PUT("/revoke/:lease_id", sshHandler.Revoke)
		}
		secured.GET("/secrets/ssh/roles/:name",
			middleware.RequirePermission(deps.AuthService, "secrets/ssh", "read"),
			sshHandler.GetRole,
		)
	}

	if deps.RotationService != nil && deps.AuthService != nil {
		secretsHandler := handlers.NewSecretsHandler(deps.SecretsService, deps.RotationService, deps.AuthService)
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
			policyGroup.DELETE("/roles/:name", policyHandler.DeleteRole)
		}
		secured.GET("/sys/policies",
			middleware.RequirePermission(deps.AuthService, "sys/policies", "read"),
			policyHandler.ListPolicies,
		)
		secured.GET("/sys/policies/:name",
			middleware.RequirePermission(deps.AuthService, "sys/policies", "read"),
			policyHandler.GetPolicy,
		)
		secured.GET("/sys/roles",
			middleware.RequirePermission(deps.AuthService, "sys/roles", "read"),
			policyHandler.ListRoles,
		)
		secured.GET("/sys/roles/:name",
			middleware.RequirePermission(deps.AuthService, "sys/roles", "read"),
			policyHandler.GetRole,
		)
		secured.POST("/sys/policies/:name/import",
			middleware.RequirePermission(deps.AuthService, "sys/policies", "write"),
			policyHandler.ImportHCL,
		)
		simHandler := handlers.NewPolicySimulateHandler(deps.AuthService)
		secured.POST("/sys/policy/simulate",
			middleware.RequirePermission(deps.AuthService, "sys/policies", "read"),
			simHandler.Simulate,
		)
	}

	if deps.LeaseService != nil && deps.AuthService != nil {
		leaseHandler := handlers.NewLeaseHandler(deps.LeaseService)
		secured.GET("/sys/leases/:lease_id",
			middleware.RequirePermission(deps.AuthService, "sys/leases", "read"),
			leaseHandler.Get,
		)
		secured.GET("/sys/leases",
			middleware.RequirePermission(deps.AuthService, "sys/leases", "read"),
			leaseHandler.List,
		)
		secured.POST("/sys/leases/renew",
			middleware.RequirePermission(deps.AuthService, "sys/leases", "write"),
			leaseHandler.Renew,
		)
		secured.POST("/sys/leases/revoke/:lease_id",
			middleware.RequirePermission(deps.AuthService, "sys/leases", "write"),
			leaseHandler.RevokeOne,
		)
		secured.PUT("/sys/leases/revoke",
			middleware.RequirePermission(deps.AuthService, "sys/leases", "write"),
			leaseHandler.BulkRevoke,
		)
		secured.POST("/sys/leases/revoke-prefix",
			middleware.RequirePermission(deps.AuthService, "sys/leases", "write"),
			leaseHandler.RevokePrefix,
		)
		secured.POST("/sys/leases/tidy",
			middleware.RequirePermission(deps.AuthService, "sys/leases", "write"),
			leaseHandler.Tidy,
		)
	}

	if deps.CubbyholeService != nil && deps.AuthService != nil {
		ch := handlers.NewCubbyholeHandler(deps.CubbyholeService)
		secured.PUT("/cubbyhole/*path",
			middleware.RequirePermission(deps.AuthService, "cubbyhole", "write"),
			ch.Put,
		)
		secured.GET("/cubbyhole/*path",
			middleware.RequirePermission(deps.AuthService, "cubbyhole", "read"),
			ch.Get,
		)
		secured.DELETE("/cubbyhole/*path",
			middleware.RequirePermission(deps.AuthService, "cubbyhole", "delete"),
			ch.Delete,
		)
	}

	if deps.WrappingService != nil && deps.AuthService != nil {
		wh := handlers.NewWrappingHandler(deps.WrappingService)
		secured.POST("/sys/wrapping/wrap",
			middleware.RequirePermission(deps.AuthService, "sys/wrapping", "write"),
			wh.Wrap,
		)
		secured.POST("/sys/wrapping/unwrap",
			middleware.RequirePermission(deps.AuthService, "sys/wrapping", "write"),
			wh.Unwrap,
		)
		secured.POST("/sys/wrapping/lookup",
			middleware.RequirePermission(deps.AuthService, "sys/wrapping", "read"),
			wh.Lookup,
		)
	}

	if deps.TransitService != nil && deps.AuthService != nil {
		th := handlers.NewTransitHandler(deps.TransitService)
		secured.POST("/transit/keys/:name",
			middleware.RequirePermission(deps.AuthService, "transit/keys", "write"),
			th.CreateKey,
		)
		secured.GET("/transit/keys/:name",
			middleware.RequirePermission(deps.AuthService, "transit/keys", "read"),
			th.ReadKey,
		)
		secured.POST("/transit/keys/:name/rotate",
			middleware.RequirePermission(deps.AuthService, "transit/keys", "write"),
			th.RotateKey,
		)
		secured.POST("/transit/encrypt/:name",
			middleware.RequirePermission(deps.AuthService, "transit/encrypt", "write"),
			th.Encrypt,
		)
		secured.POST("/transit/decrypt/:name",
			middleware.RequirePermission(deps.AuthService, "transit/decrypt", "write"),
			th.Decrypt,
		)
		secured.POST("/transit/rewrap/:name",
			middleware.RequirePermission(deps.AuthService, "transit/encrypt", "write"),
			th.Rewrap,
		)
		secured.POST("/transit/sign/:name",
			middleware.RequirePermission(deps.AuthService, "transit/sign", "write"),
			th.Sign,
		)
		secured.POST("/transit/verify/:name",
			middleware.RequirePermission(deps.AuthService, "transit/sign", "read"),
			th.Verify,
		)
		secured.POST("/transit/hmac/:name",
			middleware.RequirePermission(deps.AuthService, "transit/hmac", "write"),
			th.HMAC,
		)
	}

	if deps.IdentityService != nil && deps.AuthService != nil {
		ih := handlers.NewIdentityHandler(deps.IdentityService)
		secured.POST("/identity/entity",
			middleware.RequirePermission(deps.AuthService, "identity", "sudo"),
			ih.CreateEntity,
		)
		secured.GET("/identity/entity",
			middleware.RequirePermission(deps.AuthService, "identity", "read"),
			ih.ListEntities,
		)
		secured.GET("/identity/entity/:id",
			middleware.RequirePermission(deps.AuthService, "identity", "read"),
			ih.GetEntity,
		)
		secured.POST("/identity/entity/:id/disable",
			middleware.RequirePermission(deps.AuthService, "identity", "sudo"),
			ih.DisableEntity,
		)
		secured.POST("/identity/alias",
			middleware.RequirePermission(deps.AuthService, "identity", "sudo"),
			ih.CreateAlias,
		)
		secured.POST("/identity/group",
			middleware.RequirePermission(deps.AuthService, "identity", "sudo"),
			ih.CreateGroup,
		)
		secured.GET("/identity/group",
			middleware.RequirePermission(deps.AuthService, "identity", "read"),
			ih.ListGroups,
		)
	}

	if deps.InjectService != nil && deps.AuthService != nil {
		injectHandler := handlers.NewInjectHandler(deps.InjectService, deps.AuthService, deps.SecretsService)
		secured.POST("/inject/render",
			middleware.RequirePathCapability(deps.AuthService, "inject/render", auth.CapRead, "path", deps.AuthzAudit),
			injectHandler.Render,
		)
		secured.POST("/inject/csi/mount-audit",
			middleware.RequirePathCapability(deps.AuthService, "inject/csi", auth.CapRead, "path", deps.AuthzAudit),
			injectHandler.RecordCSIMount,
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
	if deps.AuditPackService != nil && deps.AuthService != nil {
		auditPackHandler := handlers.NewAuditPackHandler(deps.AuditPackService)
		secured.GET("/sys/audit/pack",
			middleware.RequirePermission(deps.AuthService, "audit/export", "read"),
			auditPackHandler.ExportPack,
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
