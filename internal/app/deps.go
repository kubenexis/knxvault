package app

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/crypto/masterkey"
	"github.com/kubenexis/knxvault/internal/crypto/openssl"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	databaseengine "github.com/kubenexis/knxvault/internal/engine/secrets/database"
	"github.com/kubenexis/knxvault/internal/infra/k8s"
	"github.com/kubenexis/knxvault/internal/infra/leader"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/repository/postgres"
	"github.com/kubenexis/knxvault/internal/service"
)

// Dependencies groups runtime subsystems wired at startup.
type Dependencies struct {
	Crypto     *crypto.Service
	OpenSSL    *openssl.Wrapper
	Pool       *pgxpool.Pool
	CARepo     repository.CARepository
	SecretRepo repository.SecretRepository
	AuditRepo  repository.AuditRepository
	RevokeRepo repository.RevocationRepository
	LeaseRepo  repository.LeaseRepository
	PolicyRepo repository.PolicyRepository
	RoleRepo   repository.RoleRepository
	DBRoleRepo repository.DatabaseRoleRepository

	AuthService        *auth.Service
	AuditService       *auditsvc.Service
	PKIEngine          *pkiengine.Engine
	SecretsEngine      *secretsengine.KVV2Engine
	DatabaseEngine     *databaseengine.Engine
	PKIService         *service.PKIService
	SecretsService     *service.SecretsService
	DatabaseService    *service.DatabaseService
	PolicyService      *service.PolicyService
	AuditExportService *service.AuditExportService
	TokenTTL           time.Duration

	Leader    leader.Elector
	JobRunner *JobRunner
	cfg       config.Config
}

// NewDependencies initializes crypto, storage, engines, and services from config.
func NewDependencies(ctx context.Context, cfg config.Config, log *zap.Logger) (*Dependencies, error) {
	deps := &Dependencies{
		OpenSSL:  openssl.New(cfg.OpenSSLBinary, cfg.OpenSSLTimeout),
		TokenTTL: cfg.TokenTTL,
		cfg:      cfg,
	}

	if key, err := masterkey.Load(); err == nil {
		svc, err := crypto.NewService(key)
		if err != nil {
			return nil, fmt.Errorf("crypto service: %w", err)
		}
		deps.Crypto = svc
		log.Info("master key loaded")
	} else {
		log.Warn("master key not configured; envelope encryption disabled", zap.Error(err))
	}

	if cfg.DatabaseURL != "" {
		pool, err := postgres.NewPool(ctx, cfg.DatabaseURL)
		if err != nil {
			return nil, err
		}
		deps.Pool = pool

		if cfg.AutoMigrate {
			if err := postgres.Migrate(ctx, pool); err != nil {
				pool.Close()
				return nil, fmt.Errorf("migrate database: %w", err)
			}
			log.Info("database migrations applied")
		}

		deps.CARepo = postgres.NewCARepository(pool)
		deps.SecretRepo = postgres.NewSecretRepository(pool)
		deps.AuditRepo = postgres.NewAuditRepository(pool)
		deps.RevokeRepo = postgres.NewRevocationRepository(pool)
		deps.LeaseRepo = postgres.NewLeaseRepository(pool)
		deps.PolicyRepo = postgres.NewPolicyRepository(pool)
		deps.RoleRepo = postgres.NewRoleRepository(pool)
		deps.DBRoleRepo = postgres.NewDatabaseRoleRepository(pool)
		log.Info("postgresql repositories initialized")
	} else {
		log.Warn("database not configured; using in-memory repositories")
		deps.CARepo = memory.NewCARepository()
		deps.SecretRepo = memory.NewSecretRepository()
		deps.AuditRepo = memory.NewAuditRepository()
		deps.RevokeRepo = memory.NewRevocationRepository()
		deps.LeaseRepo = memory.NewLeaseRepository()
		deps.PolicyRepo = memory.NewPolicyRepository()
		deps.RoleRepo = memory.NewRoleRepository()
		deps.DBRoleRepo = memory.NewDatabaseRoleRepository()
	}

	if deps.Crypto != nil {
		deps.PKIEngine = pkiengine.NewEngine(deps.OpenSSL, deps.Crypto, deps.CARepo, deps.RevokeRepo)
		deps.SecretsEngine = secretsengine.NewKVV2Engine(deps.SecretRepo, deps.Crypto)
		deps.DatabaseEngine = databaseengine.NewEngine(deps.DBRoleRepo, deps.LeaseRepo, deps.SecretRepo, deps.Crypto)
	}

	if deps.AuditRepo != nil {
		deps.AuditService = auditsvc.NewService(deps.AuditRepo)
		if cfg.AuditSigningKey != "" {
			deps.AuditService.SetSigningKey([]byte(cfg.AuditSigningKey))
			log.Info("audit signing key configured")
		}
	}

	if deps.PKIEngine != nil {
		deps.PKIService = service.NewPKIService(deps.PKIEngine, deps.AuditService)
	}
	if deps.SecretsEngine != nil {
		deps.SecretsService = service.NewSecretsService(deps.SecretsEngine, deps.AuditService)
	}
	if deps.DatabaseEngine != nil {
		deps.DatabaseService = service.NewDatabaseService(deps.DatabaseEngine, deps.AuditService)
	}

	tokenStore := auth.NewTokenStore(cfg.TokenTTL)
	rbac := auth.NewRBAC()
	deps.PolicyService = service.NewPolicyService(deps.PolicyRepo, deps.RoleRepo, rbac, deps.AuditService)
	if err := deps.PolicyService.LoadIntoRBAC(ctx); err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}

	if cfg.RootToken != "" {
		tokenStore.RegisterRootToken(cfg.RootToken, []string{"admin"})
		log.Info("root token registered")
	}
	deps.AuthService = auth.NewService(tokenStore, rbac, cfg.JWTSecret)
	deps.AuthService.SetRoleResolver(auth.NewRepositoryRoleResolver(deps.RoleRepo))

	if deps.AuditService != nil {
		deps.AuditExportService = service.NewAuditExportService(deps.AuditService)
	}

	deps.Leader = leader.NewNoopElector()
	if cfg.HAEnabled {
		k8sLeader, err := k8s.NewLeaderElector(k8s.LeaderConfig{
			Namespace: cfg.HANamespace,
			LeaseName: cfg.HALeaseName,
			Identity:  cfg.HAIdentity,
		})
		if err != nil {
			log.Warn("kubernetes leader election unavailable; using noop elector", zap.Error(err))
		} else {
			deps.Leader = k8sLeader
			log.Info("kubernetes leader election enabled",
				zap.String("namespace", cfg.HANamespace),
				zap.String("lease", cfg.HALeaseName),
			)
		}
	}

	deps.JobRunner = NewJobRunner(deps.Leader, deps.DatabaseService, deps.PKIService, deps.CARepo, cfg, log)

	return deps, nil
}

// Close releases database connections.
func (d *Dependencies) Close() {
	if d != nil && d.Pool != nil {
		d.Pool.Close()
	}
}

// Ready reports whether configured dependencies are reachable.
func (d *Dependencies) Ready(ctx context.Context) error {
	if d == nil {
		return nil
	}
	if d.Pool != nil {
		if err := postgres.Ping(ctx, d.Pool); err != nil {
			return fmt.Errorf("database not ready: %w", err)
		}
	}
	return nil
}

// HAEnabled reports whether HA mode is configured.
func (d *Dependencies) HAEnabled() bool {
	return d != nil && d.cfg.HAEnabled
}

// IsLeader reports whether this instance is the elected leader.
func (d *Dependencies) IsLeader() bool {
	if d == nil || d.Leader == nil {
		return true
	}
	return d.Leader.IsLeader()
}
