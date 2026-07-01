// Package ssh implements dynamic OpenSSH user certificate credentials (signed-key mode).
package ssh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
	gossh "golang.org/x/crypto/ssh"
)

const engineName = "ssh"

// Engine generates short-lived OpenSSH user certificates bound to leases.
type Engine struct {
	roles    repository.SSHRoleRepository
	leases   repository.LeaseRepository
	secrets  repository.SecretRepository
	crypto   *crypto.Service
	now      func() time.Time
	leaseGen func() (string, error)
}

// NewEngine constructs an SSH credentials engine.
func NewEngine(
	roles repository.SSHRoleRepository,
	leases repository.LeaseRepository,
	secrets repository.SecretRepository,
	cryptoSvc *crypto.Service,
) *Engine {
	return &Engine{
		roles:    roles,
		leases:   leases,
		secrets:  secrets,
		crypto:   cryptoSvc,
		now:      time.Now,
		leaseGen: newLeaseID,
	}
}

// Name returns the engine identifier.
func (e *Engine) Name() string {
	return engineName
}

// RoleConfig configures an SSH credential role.
type RoleConfig struct {
	Name         string
	TTLSeconds   int
	CAKeyPath    string
	AllowedUsers []string
	DefaultUser  string
	KeyType      string
	Extensions   map[string]string
}

// SaveRole stores or updates role configuration.
func (e *Engine) SaveRole(ctx context.Context, cfg RoleConfig) error {
	if e.roles == nil {
		return common.New(common.ErrCodeInternal, "ssh role repository not configured")
	}
	role := &domainsecrets.SSHRole{
		Name:         cfg.Name,
		TTLSeconds:   cfg.TTLSeconds,
		CAKeyPath:    cfg.CAKeyPath,
		AllowedUsers: append([]string(nil), cfg.AllowedUsers...),
		DefaultUser:  cfg.DefaultUser,
		KeyType:      cfg.KeyType,
		Extensions:   cfg.Extensions,
	}
	domainsecrets.NormalizeSSHRole(role)
	if err := role.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid ssh role", err)
	}
	return e.roles.Save(ctx, role)
}

// GetRole returns role configuration.
func (e *Engine) GetRole(ctx context.Context, name string) (*domainsecrets.SSHRole, error) {
	if e.roles == nil {
		return nil, common.New(common.ErrCodeInternal, "ssh role repository not configured")
	}
	return e.roles.Get(ctx, name)
}

// CredsRequest configures credential generation.
type CredsRequest struct {
	Role      string
	Username  string
	TTLSecond int
}

// CredsResult contains generated SSH credentials and lease metadata.
type CredsResult struct {
	LeaseID    string
	Username   string
	PrivateKey string
	SignedKey  string
	Role       string
	TTLSeconds int
	ExpiresAt  time.Time
}

// GenerateCredentials creates an ephemeral SSH key pair and signed user certificate.
func (e *Engine) GenerateCredentials(ctx context.Context, req CredsRequest) (*CredsResult, error) {
	if e.roles == nil || e.leases == nil || e.secrets == nil || e.crypto == nil {
		return nil, common.New(common.ErrCodeInternal, "ssh engine not fully configured")
	}
	if req.Role == "" {
		return nil, common.New(common.ErrCodeValidation, "role is required")
	}

	role, err := e.roles.Get(ctx, req.Role)
	if err != nil {
		return nil, err
	}
	domainsecrets.NormalizeSSHRole(role)

	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = role.DefaultUser
	}
	if username == "" && len(role.AllowedUsers) == 1 {
		username = role.AllowedUsers[0]
	}
	if username == "" {
		return nil, common.New(common.ErrCodeValidation, "username is required")
	}
	if !role.AllowedUser(username) {
		return nil, common.New(common.ErrCodeValidation, fmt.Sprintf("username %q not allowed by role", username))
	}

	ttlSeconds := role.TTLSeconds
	if req.TTLSecond > 0 {
		ttlSeconds = req.TTLSecond
	}
	if role.TTLSeconds > 0 && ttlSeconds > role.TTLSeconds {
		ttlSeconds = role.TTLSeconds
	}
	if ttlSeconds <= 0 {
		return nil, common.New(common.ErrCodeValidation, "ttl must be positive")
	}

	caSigner, err := e.loadCASigner(ctx, role.CAKeyPath)
	if err != nil {
		return nil, err
	}

	userSigner, privPEM, err := generateUserKeyPEM(role.KeyType)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "generate ssh key", err)
	}

	now := e.now().UTC()
	expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)
	signedKey, err := signUserCertificate(caSigner, userSigner, CertOptions{
		KeyID:       fmt.Sprintf("%s-%s", req.Role, username),
		Principals:  []string{username},
		ValidAfter:  now.Add(-30 * time.Second),
		ValidBefore: expiresAt,
		Extensions:  role.Extensions,
	})
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "sign ssh certificate", err)
	}

	leaseID, err := e.leaseGen()
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "generate lease id", err)
	}
	path := fmt.Sprintf("ssh/creds/%s/%s", req.Role, leaseID)

	lease := &domainsecrets.Lease{
		ID:         leaseID,
		Path:       path,
		RoleName:   req.Role,
		Engine:     engineName,
		TTLSeconds: ttlSeconds,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
		Renewable:  true,
	}
	data := map[string]any{
		"username":    username,
		"private_key": string(privPEM),
		"signed_key":  string(signedKey),
		"lease_id":    leaseID,
		"role":        req.Role,
	}
	if err := e.storeSecret(ctx, path, leaseID, ttlSeconds, expiresAt, data); err != nil {
		return nil, err
	}
	if err := e.leases.Save(ctx, lease); err != nil {
		_ = e.destroySecret(ctx, path)
		return nil, err
	}

	return &CredsResult{
		LeaseID:    leaseID,
		Username:   username,
		PrivateKey: string(privPEM),
		SignedKey:  string(signedKey),
		Role:       req.Role,
		TTLSeconds: ttlSeconds,
		ExpiresAt:  expiresAt,
	}, nil
}

// Renew extends an active lease and re-signs the user certificate.
func (e *Engine) Renew(ctx context.Context, leaseID string, ttlSeconds int) (*CredsResult, error) {
	if e.leases == nil || e.secrets == nil || e.crypto == nil || e.roles == nil {
		return nil, common.New(common.ErrCodeInternal, "ssh engine not fully configured")
	}

	lease, err := e.leases.Get(ctx, leaseID)
	if err != nil {
		return nil, err
	}
	if lease.Engine != engineName {
		return nil, common.New(common.ErrCodeValidation, "lease is not an ssh lease")
	}
	now := e.now().UTC()
	if !lease.Active(now) {
		return nil, common.New(common.ErrCodeNotFound, "lease is not active")
	}
	if !lease.Renewable {
		return nil, common.New(common.ErrCodeValidation, "lease is not renewable")
	}
	if ttlSeconds <= 0 {
		ttlSeconds = lease.TTLSeconds
	}
	role, err := e.roles.Get(ctx, lease.RoleName)
	if err != nil {
		return nil, err
	}
	if role.TTLSeconds > 0 && ttlSeconds > role.TTLSeconds {
		ttlSeconds = role.TTLSeconds
	}

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

	username, _ := data["username"].(string)
	privKey, _ := data["private_key"].(string)
	userSigner, err := parseUserSigner([]byte(privKey))
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "parse stored private key", err)
	}
	caSigner, err := e.loadCASigner(ctx, role.CAKeyPath)
	if err != nil {
		return nil, err
	}

	expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)
	signedKey, err := signUserCertificate(caSigner, userSigner, CertOptions{
		KeyID:       fmt.Sprintf("%s-%s", lease.RoleName, username),
		Principals:  []string{username},
		ValidAfter:  now.Add(-30 * time.Second),
		ValidBefore: expiresAt,
		Extensions:  role.Extensions,
	})
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "re-sign ssh certificate", err)
	}

	data["signed_key"] = string(signedKey)
	lease.TTLSeconds = ttlSeconds
	lease.ExpiresAt = expiresAt
	if err := e.leases.Save(ctx, lease); err != nil {
		return nil, err
	}
	if err := e.storeSecret(ctx, lease.Path, leaseID, ttlSeconds, expiresAt, data); err != nil {
		return nil, err
	}

	return &CredsResult{
		LeaseID:    leaseID,
		Username:   username,
		PrivateKey: privKey,
		SignedKey:  string(signedKey),
		Role:       lease.RoleName,
		TTLSeconds: ttlSeconds,
		ExpiresAt:  expiresAt,
	}, nil
}

// RevokeLease revokes a lease and destroys stored credentials.
func (e *Engine) RevokeLease(ctx context.Context, leaseID string) error {
	if e.leases == nil {
		return common.New(common.ErrCodeInternal, "lease repository not configured")
	}
	lease, err := e.leases.Get(ctx, leaseID)
	if err != nil {
		return err
	}
	if lease.Engine != engineName {
		return common.New(common.ErrCodeValidation, "lease is not an ssh lease")
	}
	now := e.now().UTC()
	if lease.RevokedAt != nil {
		return nil
	}
	if err := e.leases.Revoke(ctx, leaseID, now); err != nil {
		return err
	}
	if e.secrets != nil && e.crypto != nil {
		return e.destroySecret(ctx, lease.Path)
	}
	return nil
}

// CleanupExpired revokes expired ssh leases.
func (e *Engine) CleanupExpired(ctx context.Context, limit int) (int, error) {
	if e.leases == nil {
		return 0, common.New(common.ErrCodeInternal, "lease repository not configured")
	}
	if limit <= 0 {
		limit = 50
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
		if err := e.RevokeLease(ctx, lease.ID); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		revoked++
	}
	return revoked, firstErr
}

func (e *Engine) loadCASigner(ctx context.Context, path string) (gossh.Signer, error) {
	latest, err := e.secrets.GetLatest(ctx, path)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeValidation, "read ssh ca key from kv", err)
	}
	plain, err := e.crypto.Open(latest.DataEnc, latest.DEKEnc)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "decrypt ssh ca key", err)
	}
	var data map[string]any
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "unmarshal ssh ca key", err)
	}
	keyPEM, _ := data["private_key"].(string)
	if strings.TrimSpace(keyPEM) == "" {
		keyPEM, _ = data["private_key_pem"].(string)
	}
	if strings.TrimSpace(keyPEM) == "" {
		return nil, common.New(common.ErrCodeValidation, "ssh ca key must include private_key")
	}
	signer, err := parseCAPrivateKey([]byte(keyPEM))
	if err != nil {
		return nil, common.Wrap(common.ErrCodeValidation, "invalid ssh ca private key", err)
	}
	return signer, nil
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

func newLeaseID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "l_" + base64.RawURLEncoding.EncodeToString(raw), nil
}
