package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/api/middleware"
	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/backup"
	"github.com/kubenexis/knxvault/internal/cache"
	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/crypto/masterkey"
	"github.com/kubenexis/knxvault/internal/crypto/openssl"
	pkibackend "github.com/kubenexis/knxvault/internal/crypto/pki"
	"github.com/kubenexis/knxvault/internal/engine"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	databaseengine "github.com/kubenexis/knxvault/internal/engine/secrets/database"
	sshengine "github.com/kubenexis/knxvault/internal/engine/secrets/ssh"
	"github.com/kubenexis/knxvault/internal/infra/k8s"
	"github.com/kubenexis/knxvault/internal/infra/leader"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
	"github.com/kubenexis/knxvault/internal/inject"
	"github.com/kubenexis/knxvault/internal/notify"
	"github.com/kubenexis/knxvault/internal/raft"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/dragonboat"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

// Dependencies groups runtime subsystems wired at startup.
type Dependencies struct {
	Crypto              *crypto.Service
	MasterKey           []byte
	OpenSSL             *openssl.Wrapper
	Raft                *raft.NodeHostBundle
	CARepo              repository.CARepository
	PKIRoleRepo         repository.PKIRoleRepository
	SecretRepo          repository.SecretRepository
	AuditRepo           repository.AuditRepository
	RevokeRepo          repository.RevocationRepository
	LeaseRepo           repository.LeaseRepository
	PolicyRepo          repository.PolicyRepository
	RoleRepo            repository.RoleRepository
	TokenRepo           repository.TokenRepository
	MachineIdentityRepo repository.MachineIdentityRepository
	RotationPolicyRepo  repository.RotationPolicyRepository
	DBRoleRepo          repository.DatabaseRoleRepository
	SSHRoleRepo         repository.SSHRoleRepository
	IssuedCertRepo      repository.IssuedCertRepository

	AuthService            *auth.Service
	AuditService           *auditsvc.Service
	PKIEngine              *pkiengine.Engine
	SecretsEngine          *secretsengine.KVV2Engine
	DatabaseEngine         *databaseengine.Engine
	SSHEngine              *sshengine.Engine
	PKIService             *service.PKIService
	SecretsService         *service.SecretsService
	DatabaseService        *service.DatabaseService
	SSHService             *service.SSHService
	PolicyService          *service.PolicyService
	AuditExportService     *service.AuditExportService
	InjectService          *service.InjectService
	BackupService          *service.BackupService
	RotationService        *service.RotationService
	OrchestrationService   *service.OrchestrationService
	LeaseService           *service.LeaseService
	AuditPackService       *service.AuditPackService
	MachineIdentityService *service.MachineIdentityService
	CacheStore             cache.Store
	AuthzAudit             *middleware.AuthzAudit
	ExposureWebhook        *notify.Webhook
	EngineRegistry         *engine.Registry
	TokenTTL               time.Duration

	RateLimiter        *middleware.RateLimiter
	AuthLoginLimiter   *middleware.RateLimiter
	TokenCreateLimiter *middleware.RateLimiter
	RequestSigning     *middleware.RequestSigning

	Leader           leader.Elector
	LeaderMonitor    *leader.Monitor
	JobRunner        *JobRunner
	Seal             *SealState
	MasterKeyService *service.MasterKeyService
	cfg              config.Config
}

// NewDependencies initializes crypto, storage, engines, and services from config.
func NewDependencies(ctx context.Context, cfg config.Config, log *zap.Logger) (*Dependencies, error) {
	if err := CheckOpenSSL(cfg); err != nil {
		return nil, err
	}

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
		deps.SSHRoleRepo = repos.SSHRole
		deps.IssuedCertRepo = repos.IssuedCert
		deps.PKIRoleRepo = repos.PKIRole
		deps.TokenRepo = repos.Token
		deps.MachineIdentityRepo = repos.MachineIdentity
		deps.RotationPolicyRepo = repos.RotationPolicy
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
		deps.SSHRoleRepo = memory.NewSSHRoleRepository()
		deps.IssuedCertRepo = memory.NewIssuedCertRepository()
		deps.PKIRoleRepo = memory.NewPKIRoleRepository()
		deps.TokenRepo = memory.NewTokenRepository()
		deps.MachineIdentityRepo = memory.NewMachineIdentityRepository()
		deps.RotationPolicyRepo = memory.NewRotationPolicyRepository()
	}

	if deps.Crypto != nil {
		deps.MasterKeyService = service.NewMasterKeyService(deps.Crypto, deps.CARepo, deps.SecretRepo)
		if cfg.Raft.Enabled && cfg.UnsealKey == "" {
			return nil, fmt.Errorf("KNXVAULT_UNSEAL_KEY is required when raft is enabled")
		}
		unsealKey := resolveUnsealKey(cfg.UnsealKey, deps.MasterKey)
		if cfg.UnsealKey != "" && bytes.Equal(unsealKey, deps.MasterKey) {
			return nil, fmt.Errorf("unseal key must not equal master key")
		}
		deps.Seal = NewSealState(unsealKey)

		deps.PKIEngine = pkiengine.NewEngine(deps.OpenSSL, deps.Crypto, deps.CARepo, deps.RevokeRepo)
		deps.PKIEngine.SetBackend(selectPKIBackend(cfg, deps.OpenSSL))
		deps.PKIEngine.SetIssuedCertRepository(deps.IssuedCertRepo)
		deps.PKIEngine.SetPKIRoleRepository(deps.PKIRoleRepo)
		deps.SecretsEngine = secretsengine.NewKVV2Engine(deps.SecretRepo, deps.Crypto)
		deps.DatabaseEngine = databaseengine.NewEngine(deps.DBRoleRepo, deps.LeaseRepo, deps.SecretRepo, deps.Crypto)
		deps.SSHEngine = sshengine.NewEngine(deps.SSHRoleRepo, deps.LeaseRepo, deps.SecretRepo, deps.Crypto)

		deps.EngineRegistry = engine.NewRegistry()
		deps.EngineRegistry.Register(secretsengine.NewRegistryAdapter(deps.SecretsEngine))
		deps.EngineRegistry.Register(databaseengine.NewRegistryAdapter(deps.DatabaseEngine))
		deps.EngineRegistry.Register(sshengine.NewRegistryAdapter(deps.SSHEngine))
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
		if cfg.TenantMode {
			deps.SecretsService.SetTenantMode(true)
		}
		deps.CacheStore = cache.NewValkeyStore(cfg.ValkeyCacheURL)
		deps.SecretsService.SetCache(deps.CacheStore)
		renderer := inject.NewRenderer(service.NewKVSecretReader(deps.SecretsService))
		deps.InjectService = service.NewInjectService(renderer, deps.AuditService)
	}
	if deps.DatabaseEngine != nil {
		deps.DatabaseService = service.NewDatabaseService(deps.DatabaseEngine, deps.AuditService)
	}
	if deps.SSHEngine != nil {
		deps.SSHService = service.NewSSHService(deps.SSHEngine, deps.AuditService)
	}

	tokenStore := auth.NewTokenStore(cfg.TokenTTL)
	if deps.TokenRepo != nil {
		tokenStore.SetRepository(deps.TokenRepo)
	}
	rbac := auth.NewRBAC()
	deps.PolicyService = service.NewPolicyService(deps.PolicyRepo, deps.RoleRepo, rbac, deps.AuditService)
	if deps.Raft != nil {
		leaderWait := cfg.Raft.LeaderWait
		if leaderWait <= 0 {
			leaderWait = 10 * time.Second
		}
		deadline := time.Now().Add(leaderWait)
		for time.Now().Before(deadline) {
			if deps.Raft.Ready() {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !deps.Raft.Ready() {
			return nil, fmt.Errorf("raft cluster has no leader")
		}
	}
	if err := deps.PolicyService.LoadIntoRBAC(ctx); err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}

	if cfg.RootToken != "" {
		if err := tokenStore.RegisterRootToken(ctx, cfg.RootToken, []string{"admin"}); err != nil {
			return nil, fmt.Errorf("register root token: %w", err)
		}
		log.Info("root token registered")
	}
	deps.MachineIdentityService = service.NewMachineIdentityService(deps.MachineIdentityRepo, deps.AuditService)
	if deps.SecretsService != nil {
		deps.RotationService = service.NewRotationService(
			deps.RotationPolicyRepo,
			deps.SecretsService,
			deps.AuditService,
			cfg.RotationWebhookURL,
		)
	}
	deps.OrchestrationService = service.NewOrchestrationService(
		deps.RotationService,
		deps.DatabaseService,
		deps.SSHService,
		deps.PKIService,
		cfg.RotationWebhookURL,
	)
	deps.LeaseService = service.NewLeaseService(deps.LeaseRepo, deps.DatabaseEngine, deps.SSHEngine, deps.AuditService)
	deps.ExposureWebhook = notify.NewWebhook(cfg.ExposureWebhookURL)

	deps.AuthService = auth.NewService(tokenStore, rbac, cfg.JWTSecret)
	deps.AuthService.SetRBACSyncer(deps.PolicyService)
	deps.AuthService.SetRoleResolver(auth.NewRepositoryRoleResolver(deps.RoleRepo))
	deps.AuthService.SetOIDCValidator(auth.NewOIDCValidator(), cfg.OIDCDefaultTTL)
	deps.AuthService.SetMachineIdentityRecorder(deps.MachineIdentityService)
	deps.AuthService.SetAuditRecorder(deps.AuditService)
	deps.AuthService.SetLockoutTracker(auth.NewLockoutTracker(cfg.AuthLockoutThreshold, cfg.AuthLockoutTTL))
	deps.AuthzAudit = middleware.NewAuthzAudit(deps.AuditService)
	var tokenReviewer k8s.TokenReviewer
	if reviewer, err := k8s.NewInClusterTokenReviewer(); err == nil {
		tokenReviewer = reviewer
		log.Info("kubernetes TokenReview authentication enabled")
	} else {
		log.Warn("kubernetes TokenReview unavailable", zap.Error(err))
	}
	if cfg.Raft.Enabled && cfg.K8sAuthInsecure {
		return nil, fmt.Errorf("k8s_auth_insecure is not allowed when raft is enabled")
	}
	deps.AuthService.SetK8sLoginOptions(auth.K8sLoginOptions{
		RaftEnabled:   cfg.Raft.Enabled,
		InsecureDev:   cfg.K8sAuthInsecure,
		TokenReviewer: tokenReviewer,
	})

	if deps.AuditService != nil {
		deps.AuditExportService = service.NewAuditExportService(deps.AuditService)
		deps.AuditPackService = service.NewAuditPackService(deps.AuditService)
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
			PKIRole:    deps.PKIRoleRepo,
			DBRole:     deps.DBRoleRepo,
			SSHRole:    deps.SSHRoleRepo,
			IssuedCert: deps.IssuedCertRepo,
		}, deps.Crypto, deps.AuditService)
		deps.BackupService.SetPolicyReloader(deps.PolicyService)
		if deps.Raft != nil {
			importer := raft.NewSnapshotImporter(deps.Raft.Client)
			deps.BackupService.SetSnapshotImporter(importer)
			deps.BackupService.SetSnapshotExporter(deps.Raft.Client)
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
	deps.AuthLoginLimiter = middleware.NewRateLimiter(cfg.AuthLoginRateLimitRPM, true)
	deps.TokenCreateLimiter = middleware.NewRateLimiter(cfg.TokenCreateRateLimitRPM, true)
	deps.RequestSigning = middleware.NewRequestSigning(cfg.RequestSigningKey, cfg.RequestSigningRequired)

	deps.LeaderMonitor = leader.NewMonitor()
	deps.JobRunner = NewJobRunner(
		deps.Leader,
		deps.LeaderMonitor,
		deps.DatabaseService,
		deps.SSHService,
		deps.PKIService,
		deps.RotationService,
		deps.MasterKeyService,
		deps.CARepo,
		deps.LeaseRepo,
		cfg,
		log,
	)

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
	if d.requiresLeaderElectionHealth() && d.LeaderMonitor != nil && d.LeaderMonitor.EnforceHealth() && !d.LeaderMonitor.Running() {
		return fmt.Errorf("leader election not running")
	}
	if d.Raft != nil {
		if !d.Raft.Ready() {
			return fmt.Errorf("raft cluster has no leader")
		}
		return nil
	}
	return nil
}

func (d *Dependencies) requiresLeaderElectionHealth() bool {
	if d == nil {
		return false
	}
	return d.cfg.Raft.Enabled || d.cfg.HAEnabled
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

// Sealed reports whether the vault is operationally sealed.
func (d *Dependencies) Sealed() bool {
	if d == nil || d.Seal == nil {
		return false
	}
	return d.Seal.Sealed()
}

// IsLeader reports whether this instance is the elected leader.
func (d *Dependencies) IsLeader() bool {
	if d == nil || d.Leader == nil {
		return true
	}
	return d.Leader.IsLeader()
}

// CheckOpenSSL verifies the OpenSSL binary is available when required by configuration.
func CheckOpenSSL(cfg config.Config) error {
	if cfg.PKIBackend == "native" {
		return nil
	}
	binary := cfg.OpenSSLBinary
	if binary == "" {
		binary = "openssl"
	}
	if filepath.IsAbs(binary) {
		if _, err := os.Stat(binary); err != nil {
			return fmt.Errorf("openssl binary not found at %s: %w", binary, err)
		}
		return nil
	}
	if _, err := exec.LookPath(binary); err != nil {
		return fmt.Errorf("openssl binary %q not found in PATH: %w", binary, err)
	}
	return nil
}

func selectPKIBackend(cfg config.Config, ossl *openssl.Wrapper) pkibackend.Backend {
	switch cfg.PKIBackend {
	case "native":
		return pkibackend.NewNativeBackend()
	default:
		return pkibackend.NewOpenSSLBackend(ossl)
	}
}

func resolveUnsealKey(configured string, masterKey []byte) []byte {
	if configured != "" {
		if raw, err := base64.StdEncoding.DecodeString(configured); err == nil && len(raw) > 0 {
			return raw
		}
	}
	return append([]byte(nil), masterKey...)
}
