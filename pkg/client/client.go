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

// HealthResponse is returned by GET /health.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// ReadyResponse is returned by GET /ready.
type ReadyResponse struct {
	Status    string `json:"status"`
	Version   string `json:"version"`
	HAEnabled bool   `json:"ha_enabled,omitempty"`
	Leader    bool   `json:"leader,omitempty"`
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
	var out ReadyResponse
	if err := c.getJSON(ctx, "/ready", false, &out); err != nil {
		return nil, err
	}
	return &out, nil
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
