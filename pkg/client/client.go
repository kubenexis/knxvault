// Package client provides a lightweight HTTP SDK for the KNXVault API.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client calls the KNXVault REST API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New constructs a client with defaults.
func New(baseURL, token string) *Client {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = "http://localhost:8200"
	}
	return &Client{
		BaseURL: baseURL,
		Token:   strings.TrimSpace(token),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// ServiceStatus is returned by GET /health and GET /ready.
type ServiceStatus struct {
	Status      string `json:"status"`
	Version     string `json:"version"`
	Leader      *bool  `json:"leader,omitempty"`
	HAEnabled   bool   `json:"ha_enabled,omitempty"`
	RaftEnabled bool   `json:"raft_enabled,omitempty"`
	RaftReady   *bool  `json:"raft_ready,omitempty"`
	Sealed      *bool  `json:"sealed,omitempty"`
}

// HealthResponse is returned by GET /health.
type HealthResponse = ServiceStatus

// ReadyResponse is returned by GET /ready.
type ReadyResponse = ServiceStatus

// CapabilitiesResponse is returned by GET /sys/capabilities.
type CapabilitiesResponse struct {
	Capabilities []string `json:"capabilities"`
}

// LoginResponse is returned by POST /auth/token.
type LoginResponse struct {
	ClientToken string   `json:"client_token"`
	TTL         int      `json:"ttl"`
	Policies    []string `json:"policies"`
}

// KVWriteRequest is POST /secrets/kv/:path.
type KVWriteRequest struct {
	Data    map[string]any `json:"data"`
	Options map[string]any `json:"options,omitempty"`
}

// KVReadResponse is GET /secrets/kv/:path.
type KVReadResponse struct {
	Data map[string]any `json:"data"`
}

// CreateRootCARequest is POST /pki/root.
type CreateRootCARequest struct {
	Name       string `json:"name"`
	CommonName string `json:"common_name"`
	TTL        string `json:"ttl"`
	KeyBits    int    `json:"key_bits,omitempty"`
}

// CAResponse is returned for CA create operations.
type CAResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	CertPEM   string `json:"cert_pem"`
	Serial    string `json:"serial"`
	ExpiresAt string `json:"expires_at"`
}

// IssueCertRequest is POST /pki/issue.
type IssueCertRequest struct {
	Role       string   `json:"role"`
	CommonName string   `json:"common_name"`
	DNSNames   []string `json:"dns_names,omitempty"`
	TTL        string   `json:"ttl,omitempty"`
	AutoRenew  bool     `json:"auto_renew,omitempty"`
}

// IssueCertResponse is returned for leaf issuance.
type IssueCertResponse struct {
	CertPEM       string `json:"cert_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
	Serial        string `json:"serial"`
	ExpiresAt     string `json:"expires_at"`
}

// BackupCreateRequest is POST /sys/backup.
type BackupCreateRequest struct {
	IncludeAudit bool `json:"include_audit,omitempty"`
	AuditLimit   int  `json:"audit_limit,omitempty"`
}

// BackupCreateResponse is returned for backup creation.
type BackupCreateResponse struct {
	Format string `json:"format"`
	Data   string `json:"data"`
}

// APIError represents a KNXVault error response.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return e.Message
}

// Health calls GET /health.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var out HealthResponse
	if err := c.getJSON(ctx, "/health", false, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Ready calls GET /ready.
func (c *Client) Ready(ctx context.Context) (*ReadyResponse, error) {
	out, status, err := c.ProbeReady(ctx)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return out, &APIError{Status: status, Message: out.Status}
	}
	return out, nil
}

// ProbeReady calls GET /ready and returns the parsed body even when the service is not ready (503).
func (c *Client) ProbeReady(ctx context.Context) (*ReadyResponse, int, error) {
	return c.probeJSON(ctx, "/ready", false)
}

// Capabilities calls GET /sys/capabilities.
func (c *Client) Capabilities(ctx context.Context) (*CapabilitiesResponse, error) {
	var out CapabilitiesResponse
	if err := c.getJSON(ctx, "/sys/capabilities", true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ProbeMetrics checks whether GET /metrics is reachable.
func (c *Client) ProbeMetrics(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/metrics", nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// K8sLoginRequest is POST /auth/kubernetes.
type K8sLoginRequest struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

// LoginKubernetes exchanges a ServiceAccount JWT for a client token.
func (c *Client) LoginKubernetes(ctx context.Context, role, jwt string) (*LoginResponse, error) {
	var out LoginResponse
	err := c.postJSON(ctx, "/auth/kubernetes", false, K8sLoginRequest{Role: role, JWT: jwt}, &out)
	if err != nil {
		return nil, err
	}
	c.Token = out.ClientToken
	return &out, nil
}

// LoginToken validates a token via POST /auth/token.
func (c *Client) LoginToken(ctx context.Context, token string) (*LoginResponse, error) {
	var out LoginResponse
	err := c.postJSON(ctx, "/auth/token", false, map[string]string{"token": token}, &out)
	if err != nil {
		return nil, err
	}
	c.Token = out.ClientToken
	return &out, nil
}

// KVGet reads a secret path.
func (c *Client) KVGet(ctx context.Context, path string) (*KVReadResponse, error) {
	var out KVReadResponse
	if err := c.getJSON(ctx, "/secrets/kv/"+trimPath(path), true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// KVPut writes a secret path.
func (c *Client) KVPut(ctx context.Context, path string, data map[string]any) error {
	return c.postJSON(ctx, "/secrets/kv/"+trimPath(path), true, KVWriteRequest{Data: data}, nil)
}

// PKICreateRoot creates a self-signed root CA.
func (c *Client) PKICreateRoot(ctx context.Context, req CreateRootCARequest) (*CAResponse, error) {
	var out CAResponse
	if err := c.postJSON(ctx, "/pki/root", true, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PKIIssue issues a leaf certificate.
func (c *Client) PKIIssue(ctx context.Context, req IssueCertRequest) (*IssueCertResponse, error) {
	var out IssueCertResponse
	if err := c.postJSON(ctx, "/pki/issue", true, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// BackupCreate exports an encrypted backup archive.
func (c *Client) BackupCreate(ctx context.Context, req BackupCreateRequest) (*BackupCreateResponse, error) {
	var out BackupCreateResponse
	if err := c.postJSON(ctx, "/sys/backup", true, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RotateMasterKeyResponse is returned by POST /sys/rotate-master-key.
type RotateMasterKeyResponse struct {
	KeyVersion int `json:"key_version"`
}

// SealResponse is returned by POST /sys/seal.
type SealResponse struct {
	Sealed bool `json:"sealed"`
}

// UnsealResponse is returned by POST /sys/unseal.
type UnsealResponse struct {
	Sealed bool `json:"sealed"`
}

// RotateMasterKey activates a new envelope master key.
func (c *Client) RotateMasterKey(newKeyBase64 string) (*RotateMasterKeyResponse, error) {
	var out RotateMasterKeyResponse
	if err := c.postJSON(context.Background(), "/sys/rotate-master-key", true, map[string]string{
		"new_key": newKeyBase64,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Seal blocks mutating API operations.
func (c *Client) Seal() (*SealResponse, error) {
	var out SealResponse
	if err := c.postJSON(context.Background(), "/sys/seal", true, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Unseal restores service after seal.
func (c *Client) Unseal(keyBase64 string) (*UnsealResponse, error) {
	var out UnsealResponse
	if err := c.postJSON(context.Background(), "/sys/unseal", true, map[string]string{
		"key": keyBase64,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// BackupRestore imports an encrypted backup archive.
func (c *Client) BackupRestore(ctx context.Context, archive []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/sys/restore", bytes.NewReader(archive))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, true, nil, http.StatusNoContent)
}

func (c *Client) getJSON(ctx context.Context, path string, auth bool, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, auth, out)
}

func (c *Client) probeJSON(ctx context.Context, path string, auth bool) (*ReadyResponse, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, 0, err
	}
	if auth && c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	var out ReadyResponse
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("decode response: %w", err)
		}
	}
	return &out, resp.StatusCode, nil
}

func (c *Client) postJSON(ctx context.Context, path string, auth bool, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, auth, out)
}

func (c *Client) do(req *http.Request, auth bool, out any, expectStatus ...int) error {
	if auth && c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if len(expectStatus) > 0 && resp.StatusCode == expectStatus[0] {
		return nil
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || len(body) == 0 {
			return nil
		}
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		return nil
	}

	var apiErr struct {
		ErrorCode string `json:"error_code"`
		Message   string `json:"message"`
	}
	_ = json.Unmarshal(body, &apiErr)
	if apiErr.Message == "" {
		apiErr.Message = strings.TrimSpace(string(body))
	}
	return &APIError{Status: resp.StatusCode, Code: apiErr.ErrorCode, Message: apiErr.Message}
}

func trimPath(path string) string {
	return strings.TrimPrefix(strings.TrimSpace(path), "/")
}

// PolicyRequest creates or updates a policy.
type PolicyRequest struct {
	Effect     string         `json:"effect"`
	Resources  []string       `json:"resources"`
	Actions    []string       `json:"actions"`
	Conditions map[string]any `json:"conditions,omitempty"`
}

// PolicyResponse returns a policy.
type PolicyResponse struct {
	Name       string         `json:"name"`
	Effect     string         `json:"effect"`
	Resources  []string       `json:"resources"`
	Actions    []string       `json:"actions"`
	Conditions map[string]any `json:"conditions,omitempty"`
}

// RoleRequest creates or updates a role.
type RoleRequest struct {
	Policies                      []string `json:"policies"`
	BoundServiceAccountNames      []string `json:"bound_service_account_names,omitempty"`
	BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces,omitempty"`
}

// RoleResponse returns a role.
type RoleResponse struct {
	Name                          string   `json:"name"`
	Policies                      []string `json:"policies"`
	BoundServiceAccountNames      []string `json:"bound_service_account_names,omitempty"`
	BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces,omitempty"`
}

// AuditEntry is an exported audit record.
type AuditEntry struct {
	ID        int64          `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	Actor     string         `json:"actor"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Status    string         `json:"status"`
	Details   map[string]any `json:"details,omitempty"`
	Hash      string         `json:"hash"`
}

// AuditExportResponse is returned by GET /audit/export.
type AuditExportResponse struct {
	Entries   []AuditEntry `json:"entries"`
	HeadHash  string       `json:"head_hash"`
	Signature string       `json:"signature,omitempty"`
	SignedAt  time.Time    `json:"signed_at,omitempty"`
}

// DatabaseRoleRequest configures a database credentials role.
type DatabaseRoleRequest struct {
	TTLSeconds           int            `json:"ttl_seconds"`
	UsernamePrefix       string         `json:"username_prefix,omitempty"`
	DefaultUsername      string         `json:"default_username,omitempty"`
	CreationStatements   []string       `json:"creation_statements"`
	RevocationStatements []string       `json:"revocation_statements,omitempty"`
	ExecutionMode        string         `json:"execution_mode,omitempty"`
	AdminCredentialsPath string         `json:"admin_credentials_path,omitempty"`
	Config               map[string]any `json:"config,omitempty"`
}

// DatabaseRoleResponse returns database role configuration.
type DatabaseRoleResponse struct {
	Name                 string         `json:"name"`
	TTLSeconds           int            `json:"ttl_seconds"`
	UsernamePrefix       string         `json:"username_prefix,omitempty"`
	DefaultUsername      string         `json:"default_username,omitempty"`
	CreationStatements   []string       `json:"creation_statements"`
	RevocationStatements []string       `json:"revocation_statements,omitempty"`
	ExecutionMode        string         `json:"execution_mode,omitempty"`
	AdminCredentialsPath string         `json:"admin_credentials_path,omitempty"`
	Config               map[string]any `json:"config,omitempty"`
}

// DatabaseCredsResponse is returned for credential generation.
type DatabaseCredsResponse struct {
	LeaseID    string   `json:"lease_id"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	Role       string   `json:"role"`
	TTLSeconds int      `json:"ttl_seconds"`
	ExpiresAt  string   `json:"expires_at"`
	Statements []string `json:"statements,omitempty"`
}

// RaftAddNodeRequest adds a Raft peer.
type RaftAddNodeRequest struct {
	NodeID  uint64 `json:"node_id"`
	Address string `json:"address"`
}

// RaftRemoveNodeRequest removes a Raft peer.
type RaftRemoveNodeRequest struct {
	NodeID uint64 `json:"node_id"`
}

// RotationRunRequest triggers orchestrated rotation.
type RotationRunRequest struct {
	DBGrace  string `json:"db_grace,omitempty"`
	PKIGrace string `json:"pki_grace,omitempty"`
}

// RotationRunResponse summarizes orchestrated rotation.
type RotationRunResponse struct {
	KVRotated    int `json:"kv_rotated"`
	DBRenewed    int `json:"db_leases_renewed"`
	PKIRenewed   int `json:"pki_certs_renewed"`
	TotalActions int `json:"total_actions"`
}

// IssueListenerTLSRequest issues listener TLS material.
type IssueListenerTLSRequest struct {
	Role       string   `json:"role"`
	CommonName string   `json:"common_name"`
	DNSNames   []string `json:"dns_names,omitempty"`
	CertFile   string   `json:"cert_file,omitempty"`
	KeyFile    string   `json:"key_file,omitempty"`
	TTL        string   `json:"ttl,omitempty"`
}

// IssueListenerTLSResponse returns issued listener TLS material.
type IssueListenerTLSResponse struct {
	CertPEM       string `json:"cert_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
	Serial        string `json:"serial"`
	ExpiresAt     string `json:"expires_at"`
	CertFile      string `json:"cert_file,omitempty"`
	KeyFile       string `json:"key_file,omitempty"`
}

// PutPolicy stores a policy.
func (c *Client) PutPolicy(ctx context.Context, name string, req PolicyRequest) error {
	return c.putJSON(ctx, "/sys/policies/"+trimPath(name), true, req, nil, http.StatusNoContent)
}

// GetPolicy returns a policy.
func (c *Client) GetPolicy(ctx context.Context, name string) (*PolicyResponse, error) {
	var out PolicyResponse
	if err := c.getJSON(ctx, "/sys/policies/"+trimPath(name), true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListPolicies returns all policies.
func (c *Client) ListPolicies(ctx context.Context) ([]PolicyResponse, error) {
	var out struct {
		Policies []PolicyResponse `json:"policies"`
	}
	if err := c.getJSON(ctx, "/sys/policies", true, &out); err != nil {
		return nil, err
	}
	return out.Policies, nil
}

// DeletePolicy removes a policy.
func (c *Client) DeletePolicy(ctx context.Context, name string) error {
	return c.deleteJSON(ctx, "/sys/policies/"+trimPath(name), true, nil, http.StatusNoContent)
}

// PutRole stores a role.
func (c *Client) PutRole(ctx context.Context, name string, req RoleRequest) error {
	return c.putJSON(ctx, "/sys/roles/"+trimPath(name), true, req, nil, http.StatusNoContent)
}

// GetRole returns a role.
func (c *Client) GetRole(ctx context.Context, name string) (*RoleResponse, error) {
	var out RoleResponse
	if err := c.getJSON(ctx, "/sys/roles/"+trimPath(name), true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AuditExport exports audit entries.
func (c *Client) AuditExport(ctx context.Context, limit int) (*AuditExportResponse, error) {
	path := "/audit/export"
	if limit > 0 {
		path += fmt.Sprintf("?limit=%d", limit)
	}
	var out AuditExportResponse
	if err := c.getJSON(ctx, path, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutDatabaseRole stores a database role.
func (c *Client) PutDatabaseRole(ctx context.Context, name string, req DatabaseRoleRequest) error {
	return c.putJSON(ctx, "/secrets/database/roles/"+trimPath(name), true, req, nil, http.StatusNoContent)
}

// GetDatabaseRole returns a database role.
func (c *Client) GetDatabaseRole(ctx context.Context, name string) (*DatabaseRoleResponse, error) {
	var out DatabaseRoleResponse
	if err := c.getJSON(ctx, "/secrets/database/roles/"+trimPath(name), true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GenerateDatabaseCreds issues database credentials.
func (c *Client) GenerateDatabaseCreds(ctx context.Context, role string, ttlSeconds int) (*DatabaseCredsResponse, error) {
	body := map[string]any{}
	if ttlSeconds > 0 {
		body["ttl_seconds"] = ttlSeconds
	}
	var out DatabaseCredsResponse
	if err := c.postJSON(ctx, "/secrets/database/creds/"+trimPath(role), true, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RaftAddNode adds a Raft cluster member.
func (c *Client) RaftAddNode(ctx context.Context, req RaftAddNodeRequest) error {
	return c.postJSON(ctx, "/sys/raft/add-node", true, req, nil)
}

// RaftRemoveNode removes a Raft cluster member.
func (c *Client) RaftRemoveNode(ctx context.Context, req RaftRemoveNodeRequest) error {
	return c.postJSON(ctx, "/sys/raft/remove-node", true, req, nil)
}

// RunRotation triggers orchestrated rotation.
func (c *Client) RunRotation(ctx context.Context, req RotationRunRequest) (*RotationRunResponse, error) {
	var out RotationRunResponse
	if err := c.postJSON(ctx, "/sys/rotation/run", true, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// IssueListenerTLS issues TLS material for the API listener.
func (c *Client) IssueListenerTLS(ctx context.Context, req IssueListenerTLSRequest) (*IssueListenerTLSResponse, error) {
	var out IssueListenerTLSResponse
	if err := c.postJSON(ctx, "/sys/tls/issue-listener", true, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) putJSON(ctx context.Context, path string, auth bool, body any, out any, expectStatus ...int) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, auth, out, expectStatus...)
}

func (c *Client) deleteJSON(ctx context.Context, path string, auth bool, out any, expectStatus ...int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, auth, out, expectStatus...)
}
