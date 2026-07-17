// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package database implements the dynamic database credentials engine (LLD §4.B, Phase 2).
package database

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/engine/secrets/leaseutil"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/tenant"
)

const engineName = "database"

// Engine generates short-lived database credentials with lease tracking.
type Engine struct {
	roles    repository.DatabaseRoleRepository
	leases   repository.LeaseRepository
	secrets  repository.SecretRepository
	crypto   *crypto.Service
	sql      SQLRunner
	now      func() time.Time
	leaseGen func() (string, error)
}

// NewEngine constructs a database credentials engine.
func NewEngine(
	roles repository.DatabaseRoleRepository,
	leases repository.LeaseRepository,
	secrets repository.SecretRepository,
	cryptoSvc *crypto.Service,
) *Engine {
	return &Engine{
		roles:    roles,
		leases:   leases,
		secrets:  secrets,
		crypto:   cryptoSvc,
		sql:      DefaultSQLRunner{},
		now:      time.Now,
		leaseGen: newLeaseID,
	}
}

// SetSQLRunner overrides the SQL executor (tests).
func (e *Engine) SetSQLRunner(runner SQLRunner) {
	if e != nil {
		e.sql = runner
	}
}

// Name returns the engine identifier.
func (e *Engine) Name() string {
	return engineName
}

// RoleConfig configures a database credential role.
type RoleConfig struct {
	Name                 string
	TTLSeconds           int
	DefaultTTL           int
	MaxTTL               int
	Period               int
	Renewable            *bool
	MaxLeases            int
	UsernamePrefix       string
	DefaultUsername      string
	CreationStatements   []string
	RevocationStatements []string
	ExecutionMode        string
	AdminCredentialsPath string
	Config               map[string]any
}

// SaveRole stores or updates role configuration.
func (e *Engine) SaveRole(ctx context.Context, cfg RoleConfig) error {
	if e.roles == nil {
		return common.New(common.ErrCodeInternal, "database role repository not configured")
	}
	renewable := true
	if cfg.Renewable != nil {
		renewable = *cfg.Renewable
	}
	role := &domainsecrets.DatabaseRole{
		Name:                 cfg.Name,
		TTLSeconds:           cfg.TTLSeconds,
		DefaultTTL:           cfg.DefaultTTL,
		MaxTTL:               cfg.MaxTTL,
		Period:               cfg.Period,
		Renewable:            renewable,
		MaxLeases:            cfg.MaxLeases,
		UsernamePrefix:       cfg.UsernamePrefix,
		DefaultUsername:      cfg.DefaultUsername,
		CreationStatements:   cfg.CreationStatements,
		RevocationStatements: cfg.RevocationStatements,
		ExecutionMode:        cfg.ExecutionMode,
		AdminCredentialsPath: cfg.AdminCredentialsPath,
		Config:               cfg.Config,
	}
	if role.TTLSeconds <= 0 {
		role.TTLSeconds = 3600
	}
	if role.UsernamePrefix == "" {
		role.UsernamePrefix = "v-"
	}
	domainsecrets.NormalizeDatabaseRole(role)
	applyDBTypeDefaults(role)
	if err := role.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid database role", err)
	}
	return e.roles.Save(ctx, role)
}

// GetRole returns role configuration.
func (e *Engine) GetRole(ctx context.Context, name string) (*domainsecrets.DatabaseRole, error) {
	if e.roles == nil {
		return nil, common.New(common.ErrCodeInternal, "database role repository not configured")
	}
	return e.roles.Get(ctx, name)
}

// CredsRequest configures credential generation.
type CredsRequest struct {
	Role      string
	TTL       string
	TTLSecond int
	// TokenID is the hashed client token that issued the lease (cascade revoke).
	TokenID string
	// Tenant is optional namespace for lease ID scoping (W64-01).
	Tenant string
	// TenantMode enables lease ID prefixing.
	TenantMode bool
}

// CredsResult contains generated credentials and lease metadata.
type CredsResult struct {
	LeaseID    string
	Username   string
	Password   string
	Role       string
	TTLSeconds int
	MaxTTL     int
	ExpiresAt  time.Time
	Statements []string
	Warnings   []string
}

// GenerateCredentials creates ephemeral credentials bound to a lease.
func (e *Engine) GenerateCredentials(ctx context.Context, req CredsRequest) (*CredsResult, error) {
	if e.roles == nil || e.leases == nil || e.secrets == nil || e.crypto == nil {
		return nil, common.New(common.ErrCodeInternal, "database engine not fully configured")
	}
	if req.Role == "" {
		return nil, common.New(common.ErrCodeValidation, "role is required")
	}

	role, err := e.roles.Get(ctx, req.Role)
	if err != nil {
		return nil, err
	}
	domainsecrets.NormalizeDatabaseRole(role)
	tuning := domainsecrets.LeaseTuningFromDatabaseRole(role)
	if err := leaseutil.CheckMaxLeases(ctx, e.leases, engineName, req.Role, tuning); err != nil {
		return nil, err
	}
	ttlSeconds, err := tuning.ResolveIssueTTL(req.TTLSecond)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeValidation, "invalid ttl", err)
	}

	leaseID, err := e.leaseGen()
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "generate lease id", err)
	}
	if req.TenantMode {
		leaseID = tenant.ScopeLeaseID(req.Tenant, leaseID, true)
	}

	username, err := e.generateUsername(role)
	if err != nil {
		return nil, err
	}
	password, err := randomToken(24)
	if err != nil {
		return nil, err
	}

	now := e.now().UTC()
	expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)
	path := fmt.Sprintf("database/creds/%s/%s", req.Role, leaseID)

	lease := &domainsecrets.Lease{
		ID:         leaseID,
		Path:       path,
		RoleName:   req.Role,
		Engine:     engineName,
		TTLSeconds: ttlSeconds,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
		Renewable:  tuning.Renewable,
		TokenID:    req.TokenID,
	}
	data := map[string]any{
		"username": username,
		"password": password,
		"lease_id": leaseID,
		"role":     req.Role,
	}
	if err := e.storeSecret(ctx, path, leaseID, ttlSeconds, expiresAt, data); err != nil {
		return nil, err
	}
	if err := e.leases.Save(ctx, lease); err != nil {
		_ = e.destroySecret(ctx, path)
		return nil, err
	}

	statements := renderStatementsForRole(role.CreationStatements, role, username, password, expiresAt)
	if role.ExecutionMode == domainsecrets.ExecutionModeManaged {
		connURL, err := e.adminConnectionURL(ctx, role)
		if err != nil {
			return nil, err
		}
		if e.sql == nil {
			return nil, common.New(common.ErrCodeInternal, "sql runner not configured")
		}
		if err := e.sql.ExecStatements(ctx, connURL, statements); err != nil {
			_ = e.destroySecret(ctx, path)
			_ = e.leases.Revoke(ctx, leaseID, now)
			return nil, common.Wrap(common.ErrCodeInternal, "execute creation statements", err)
		}
	}
	return &CredsResult{
		LeaseID:    leaseID,
		Username:   username,
		Password:   password,
		Role:       req.Role,
		TTLSeconds: ttlSeconds,
		MaxTTL:     tuning.MaxTTL,
		ExpiresAt:  expiresAt,
		Statements: statements,
		Warnings:   domainsecrets.LeaseWarnings(now, expiresAt, ttlSeconds),
	}, nil
}

// Renew extends an active lease TTL.
func (e *Engine) Renew(ctx context.Context, leaseID string, ttlSeconds int) (*CredsResult, error) {
	if e.leases == nil || e.secrets == nil || e.crypto == nil {
		return nil, common.New(common.ErrCodeInternal, "database engine not fully configured")
	}

	lease, err := e.leases.Get(ctx, leaseID)
	if err != nil {
		return nil, err
	}
	now := e.now().UTC()
	if !lease.Active(now) {
		return nil, common.New(common.ErrCodeNotFound, "lease is not active")
	}
	if !lease.Renewable {
		return nil, common.New(common.ErrCodeValidation, "lease is not renewable")
	}
	role, err := e.roles.Get(ctx, lease.RoleName)
	if err != nil {
		return nil, err
	}
	tuning := domainsecrets.LeaseTuningFromDatabaseRole(role)
	ttlSeconds = tuning.ResolveRenewTTL(ttlSeconds, lease.TTLSeconds, now, lease.ExpiresAt)

	latest, err := e.secrets.GetLatest(ctx, lease.Path)
	if err != nil {
		return nil, err
	}
	plain, err := e.crypto.Open(latest.DataEnc, latest.DEKEnc)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "decrypt credentials", err)
	}
	var data map[string]any
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "unmarshal credentials", err)
	}

	expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)
	lease.TTLSeconds = ttlSeconds
	lease.ExpiresAt = expiresAt
	if err := e.leases.Save(ctx, lease); err != nil {
		return nil, err
	}
	if err := e.storeSecret(ctx, lease.Path, leaseID, ttlSeconds, expiresAt, data); err != nil {
		return nil, err
	}

	username, _ := data["username"].(string)
	password, _ := data["password"].(string)
	return &CredsResult{
		LeaseID:    leaseID,
		Username:   username,
		Password:   password,
		Role:       lease.RoleName,
		TTLSeconds: ttlSeconds,
		MaxTTL:     tuning.MaxTTL,
		ExpiresAt:  expiresAt,
		Statements: renderStatementsForRole(role.CreationStatements, role, username, password, expiresAt),
		Warnings:   domainsecrets.LeaseWarnings(now, expiresAt, ttlSeconds),
	}, nil
}

// RevokeResult contains optional client-mode revocation SQL (W36-19).
type RevokeResult struct {
	RevocationStatements []string `json:"revocation_statements,omitempty"`
}

// RevokeLease revokes a lease and its stored credentials.
func (e *Engine) RevokeLease(ctx context.Context, leaseID string) (*RevokeResult, error) {
	if e.leases == nil {
		return nil, common.New(common.ErrCodeInternal, "lease repository not configured")
	}
	lease, err := e.leases.Get(ctx, leaseID)
	if err != nil {
		return nil, err
	}
	now := e.now().UTC()
	if lease.RevokedAt != nil {
		return &RevokeResult{}, nil
	}
	var username, password string
	if latest, err := e.secrets.GetLatest(ctx, lease.Path); err == nil {
		if plain, err := e.crypto.Open(latest.DataEnc, latest.DEKEnc); err == nil {
			var data map[string]any
			if json.Unmarshal(plain, &data) == nil {
				username, _ = data["username"].(string)
				password, _ = data["password"].(string)
			}
		}
	}
	role, _ := e.roles.Get(ctx, lease.RoleName)
	var result RevokeResult
	if role != nil && len(role.RevocationStatements) > 0 && username != "" {
		result.RevocationStatements = renderStatementsForRole(role.RevocationStatements, role, username, password, now)
	}
	if err := e.leases.Revoke(ctx, leaseID, now); err != nil {
		return nil, err
	}
	if role != nil && role.ExecutionMode == domainsecrets.ExecutionModeManaged {
		if len(result.RevocationStatements) > 0 {
			connURL, err := e.adminConnectionURL(ctx, role)
			if err != nil {
				return nil, common.Wrap(common.ErrCodeInternal, "managed revoke: admin credentials", err)
			}
			if e.sql == nil {
				return nil, common.New(common.ErrCodeInternal, "sql runner not configured")
			}
			if err := e.sql.ExecStatements(ctx, connURL, result.RevocationStatements); err != nil {
				return nil, common.Wrap(common.ErrCodeInternal, "managed revoke: execute revocation statements", err)
			}
		}
		result.RevocationStatements = nil
	}
	if e.secrets != nil && e.crypto != nil {
		if err := e.destroySecret(ctx, lease.Path); err != nil {
			return nil, err
		}
	}
	return &result, nil
}

func (e *Engine) adminConnectionURL(ctx context.Context, role *domainsecrets.DatabaseRole) (string, error) {
	if role.AdminCredentialsPath == "" {
		return "", common.New(common.ErrCodeValidation, "admin_credentials_path is required for managed mode")
	}
	latest, err := e.secrets.GetLatest(ctx, role.AdminCredentialsPath)
	if err != nil {
		return "", common.Wrap(common.ErrCodeValidation, "read admin credentials from kv", err)
	}
	plain, err := e.crypto.Open(latest.DataEnc, latest.DEKEnc)
	if err != nil {
		return "", common.Wrap(common.ErrCodeInternal, "decrypt admin credentials", err)
	}
	var data map[string]any
	if err := json.Unmarshal(plain, &data); err != nil {
		return "", common.Wrap(common.ErrCodeInternal, "unmarshal admin credentials", err)
	}
	connURL, err := BuildConnectionURL(data, role.Config)
	if err != nil {
		return "", common.Wrap(common.ErrCodeValidation, "admin credentials", err)
	}
	return connURL, nil
}

// RenewExpiring renews active leases expiring within the grace window.
func (e *Engine) RenewExpiring(ctx context.Context, grace time.Duration, limit int) (int, error) {
	if e.leases == nil {
		return 0, common.New(common.ErrCodeInternal, "lease repository not configured")
	}
	if limit <= 0 {
		limit = 50
	}
	now := e.now().UTC()
	deadline := now.Add(grace)
	leases, err := e.leases.List(ctx)
	if err != nil {
		return 0, err
	}
	renewed := 0
	for _, lease := range leases {
		if renewed >= limit {
			break
		}
		if !lease.Active(now) || !lease.Renewable {
			continue
		}
		if lease.ExpiresAt.After(deadline) {
			continue
		}
		if _, err := e.Renew(ctx, lease.ID, lease.TTLSeconds); err != nil {
			continue
		}
		renewed++
	}
	return renewed, nil
}

// CleanupExpired revokes leases that have passed their expiration time.
func (e *Engine) CleanupExpired(ctx context.Context, limit int) (int, error) {
	if e.leases == nil {
		return 0, common.New(common.ErrCodeInternal, "lease repository not configured")
	}
	now := e.now().UTC()
	expired, err := e.leases.ListExpired(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	revoked := 0
	var firstErr error
	for _, lease := range expired {
		if lease.Engine != engineName {
			continue
		}
		if _, err := e.RevokeLease(ctx, lease.ID); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		revoked++
	}
	return revoked, firstErr
}

func (e *Engine) storeSecret(
	ctx context.Context,
	path, leaseID string,
	ttlSeconds int,
	expiresAt time.Time,
	data map[string]any,
) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return common.Wrap(common.ErrCodeInternal, "marshal credentials", err)
	}
	dataEnc, dekEnc, err := e.crypto.Seal(payload)
	if err != nil {
		return common.Wrap(common.ErrCodeInternal, "encrypt credentials", err)
	}

	sv := &domainsecrets.SecretVersion{
		ID:         uuid.New(),
		Path:       path,
		DataEnc:    dataEnc,
		DEKEnc:     dekEnc,
		LeaseID:    &leaseID,
		TTLSeconds: &ttlSeconds,
		CreatedAt:  e.now().UTC(),
		ExpiresAt:  &expiresAt,
	}
	_, err = e.secrets.PutAtomic(ctx, sv, nil, 0)
	return err
}

func (e *Engine) destroySecret(ctx context.Context, path string) error {
	latest, err := e.secrets.GetLatest(ctx, path)
	if err != nil {
		return nil
	}
	if latest.Destroyed {
		return nil
	}
	return e.secrets.DestroyVersion(ctx, path, latest.Version)
}

func (e *Engine) generateUsername(role *domainsecrets.DatabaseRole) (string, error) {
	if role.DefaultUsername != "" {
		return role.DefaultUsername, nil
	}
	suffix, err := randomToken(8)
	if err != nil {
		return "", err
	}
	return role.UsernamePrefix + role.Name + "-" + suffix, nil
}

func newLeaseID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "l_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func randomToken(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
