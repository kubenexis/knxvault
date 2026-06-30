package app

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/api/middleware"
	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/backup"
	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/crypto/masterkey"
	"github.com/kubenexis/knxvault/internal/crypto/openssl"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	databaseengine "github.com/kubenexis/knxvault/internal/engine/secrets/database"
	"github.com/kubenexis/knxvault/internal/infra/k8s"
	"github.com/kubenexis/knxvault/internal/infra/leader"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
	"github.com/kubenexis/knxvault/internal/inject"
	"github.com/kubenexis/knxvault/internal/raft"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/dragonboat"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

// Dependencies groups runtime subsystems wired at startup.
type Dependencies struct {
	Crypto         *crypto.Service
	MasterKey      []byte
	OpenSSL        *openssl.Wrapper
	Raft           *raft.NodeHostBundle
	CARepo         repository.CARepository
	PKIRoleRepo    repository.PKIRoleRepository
	SecretRepo     repository.SecretRepository
	AuditRepo      repository.AuditRepository
	RevokeRepo     repository.RevocationRepository
	LeaseRepo      repository.LeaseRepository
	PolicyRepo     repository.PolicyRepository
	RoleRepo       repository.RoleRepository
	DBRoleRepo     repository.DatabaseRoleRepository
	IssuedCertRepo repository.IssuedCertRepository

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
	InjectService      *service.InjectService
	BackupService      *service.BackupService
	TokenTTL           time.Duration

	RateLimiter    *middleware.RateLimiter
	RequestSigning *middleware.RequestSigning

	Leader    leader.Elector
	JobRunner *JobRunner
	cfg       config.Config
}

// NewDependencies initializes crypto, storage, engines, and services from config.
func NewDependencies(ctx context.Context, cfg config.Config, log *zap.Logger) (*Dependencies, error) {
	breaker := openssl.NewBreaker(3, 30*time.Second)
	breaker.SetOnStateChange(metrics.SetOpenSSLBreakerOpen)
	ossl := openssl.New(cfg.OpenSSLBinary, cfg.OpenSSLTimeout)
	ossl.SetBreaker(breaker)
	deps := &Dependencies{
		OpenSSL:  ossl,
		TokenTTL: cfg.TokenTTL,
		cfg:      cfg,
	}

	if key, err := masterkey.Load(); err == nil {
		svc, err := crypto.NewService(key)
		if err != nil {
			return nil, fmt.Errorf("crypto service: %w", err)
		}
		deps.Crypto = svc
		deps.MasterKey = append([]byte(nil), key...)
		log.Info("master key loaded")
	} else if cfg.Raft.Enabled {
		return nil, fmt.Errorf("master key required when raft is enabled: %w", err)
	} else {
		log.Warn("master key not configured; envelope encryption disabled", zap.Error(err))
	}

	if cfg.Raft.Enabled {
		raftCfg := cfg.Raft
		members, err := raft.ParseInitialMembers(raftCfg.InitialMembersRaw)
		if err != nil {
			return nil, fmt.Errorf("raft initial members: %w", err)
		}
		raftCfg.InitialMembers = members

		bundle, err := raft.StartNodeHost(raftCfg)
		if err != nil {
			return nil, err
		}
		deps.Raft = bundle
		repos := dragonboat.NewRepos(bundle.Client)
		deps.CARepo = repos.CA
		deps.SecretRepo = repos.Secret
		deps.AuditRepo = repos.Audit
		deps.RevokeRepo = repos.Revoke
		deps.LeaseRepo = repos.Lease
		deps.PolicyRepo = repos.Policy
		deps.RoleRepo = repos.Role
		deps.DBRoleRepo = repos.DBRole
		deps.IssuedCertRepo = repos.IssuedCert
		deps.PKIRoleRepo = repos.PKIRole
		deps.Leader = raft.NewLeaderElector(bundle.Client)
		log.Info("dragonboat raft repositories initialized",
			zap.Uint64("node_id", raftCfg.NodeID),
			zap.String("raft_address", raftCfg.RaftAddress),
		)
	} else {
		log.Warn("raft disabled; using in-memory repositories")
		deps.CARepo = memory.NewCARepository()
		deps.SecretRepo = memory.NewSecretRepository()
		deps.AuditRepo = memory.NewAuditRepository()
		deps.RevokeRepo = memory.NewRevocationRepository()
		deps.LeaseRepo = memory.NewLeaseRepository()
		deps.PolicyRepo = memory.NewPolicyRepository()
		deps.RoleRepo = memory.NewRoleRepository()
		deps.DBRoleRepo = memory.NewDatabaseRoleRepository()
		deps.IssuedCertRepo = memory.NewIssuedCertRepository()
		deps.PKIRoleRepo = memory.NewPKIRoleRepository()
	}

	if deps.Crypto != nil {
		deps.PKIEngine = pkiengine.NewEngine(deps.OpenSSL, deps.Crypto, deps.CARepo, deps.RevokeRepo)
		deps.PKIEngine.SetIssuedCertRepository(deps.IssuedCertRepo)
		deps.PKIEngine.SetPKIRoleRepository(deps.PKIRoleRepo)
		deps.SecretsEngine = secretsengine.NewKVV2Engine(deps.SecretRepo, deps.Crypto)
		deps.DatabaseEngine = databaseengine.NewEngine(deps.DBRoleRepo, deps.LeaseRepo, deps.SecretRepo, deps.Crypto)
	}

	if deps.AuditRepo != nil {
		deps.AuditService = auditsvc.NewService(deps.AuditRepo)
		if cfg.AuditSigningKey != "" {
			deps.AuditService.SetSigningKey([]byte(cfg.AuditSigningKey))
			log.Info("audit signing key configured")
		}
		if cfg.AuditForwardURL != "" {
			deps.AuditService.SetForwardURL(cfg.AuditForwardURL)
			log.Info("audit forward URL configured", zap.String("url", cfg.AuditForwardURL))
		}
	}

	if deps.PKIEngine != nil {
		deps.PKIService = service.NewPKIService(deps.PKIEngine, deps.AuditService)
	}
	if deps.SecretsEngine != nil {
		deps.SecretsService = service.NewSecretsService(deps.SecretsEngine, deps.AuditService)
		renderer := inject.NewRenderer(service.NewKVSecretReader(deps.SecretsService))
		deps.InjectService = service.NewInjectService(renderer, deps.AuditService)
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
	var tokenReviewer k8s.TokenReviewer
	if reviewer, err := k8s.NewInClusterTokenReviewer(); err == nil {
		tokenReviewer = reviewer
		log.Info("kubernetes TokenReview authentication enabled")
	} else {
		log.Warn("kubernetes TokenReview unavailable", zap.Error(err))
	}
	deps.AuthService.SetK8sLoginOptions(auth.K8sLoginOptions{
		RaftEnabled:   cfg.Raft.Enabled,
		InsecureDev:   cfg.K8sAuthInsecure,
		TokenReviewer: tokenReviewer,
	})

	if deps.AuditService != nil {
		deps.AuditExportService = service.NewAuditExportService(deps.AuditService)
	}

	if deps.Crypto != nil {
		deps.BackupService = service.NewBackupService(backup.Repos{
			CA:         deps.CARepo,
			Secret:     deps.SecretRepo,
			Audit:      deps.AuditRepo,
			Revoke:     deps.RevokeRepo,
			Lease:      deps.LeaseRepo,
			Policy:     deps.PolicyRepo,
			Role:       deps.RoleRepo,
			DBRole:     deps.DBRoleRepo,
			IssuedCert: deps.IssuedCertRepo,
		}, deps.Crypto, deps.AuditService)
		if deps.Raft != nil {
			importer := raft.NewSnapshotImporter(deps.Raft.Client)
			deps.BackupService.SetSnapshotImporter(importer)
			deps.BackupService.SetSnapshotRequester(deps.Raft.Client)
		}
	}

	if deps.Leader == nil {
		deps.Leader = leader.NewNoopElector()
	}
	if !cfg.Raft.Enabled && cfg.HAEnabled {
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

	deps.RateLimiter = middleware.NewRateLimiter(cfg.RateLimitRPM, cfg.RateLimitEnabled)
	deps.RequestSigning = middleware.NewRequestSigning(cfg.RequestSigningKey, cfg.RequestSigningRequired)

	deps.JobRunner = NewJobRunner(deps.Leader, deps.DatabaseService, deps.PKIService, deps.CARepo, cfg, log)

	return deps, nil
}

// Close releases database connections and stops Raft.
func (d *Dependencies) Close() {
	if d == nil {
		return
	}
	if d.Raft != nil {
		d.Raft.Stop()
	}
}

// Ready reports whether configured dependencies are reachable.
func (d *Dependencies) Ready(ctx context.Context) error {
	if d == nil {
		return nil
	}
	if d.Raft != nil {
		if !d.Raft.Ready() {
			return fmt.Errorf("raft cluster has no leader")
		}
		return nil
	}
	return nil
}

// HAEnabled reports whether HA mode is configured.
func (d *Dependencies) HAEnabled() bool {
	if d == nil {
		return false
	}
	return d.cfg.Raft.Enabled || d.cfg.HAEnabled
}

// RaftEnabled reports whether Dragonboat storage is active.
func (d *Dependencies) RaftEnabled() bool {
	return d != nil && d.cfg.Raft.Enabled
}

// RaftReady reports whether the Raft cluster has a known leader.
func (d *Dependencies) RaftReady() bool {
	return d != nil && d.Raft != nil && d.Raft.Ready()
}

// IsLeader reports whether this instance is the elected leader.
func (d *Dependencies) IsLeader() bool {
	if d == nil || d.Leader == nil {
		return true
	}
	return d.Leader.IsLeader()
}