package csi

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

// VaultClient exchanges Kubernetes JWTs and reads KV secrets from KNXVault.
type VaultClient struct {
	HTTP *http.Client
}

// NewVaultClient constructs a VaultClient with defaults.
func NewVaultClient() *VaultClient {
	return &VaultClient{HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type loginRequest struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

type loginResponse struct {
	ClientToken string `json:"client_token"`
}

type kvReadResponse struct {
	Data     map[string]any `json:"data"`
	Metadata struct {
		Version int `json:"version"`
	} `json:"metadata"`
}

// LoginKubernetes exchanges a ServiceAccount JWT for a client token.
func (v *VaultClient) LoginKubernetes(ctx context.Context, addr, role, jwt string) (string, error) {
	var out loginResponse
	if err := v.postJSON(ctx, addr, "/auth/kubernetes", false, "", loginRequest{Role: role, JWT: jwt}, &out); err != nil {
		return "", err
	}
	if out.ClientToken == "" {
		return "", fmt.Errorf("empty client token")
	}
	return out.ClientToken, nil
}

// ReadKV fetches the latest version of a KV secret path.
func (v *VaultClient) ReadKV(ctx context.Context, addr, token, path string) (map[string]any, int, error) {
	var out kvReadResponse
	if err := v.getJSON(ctx, addr, "/secrets/kv/"+trimPath(path), true, token, &out); err != nil {
		return nil, 0, err
	}
	return out.Data, out.Metadata.Version, nil
}

func (v *VaultClient) getJSON(ctx context.Context, addr, path string, auth bool, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(addr, path), nil)
	if err != nil {
		return err
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return v.do(req, out)
}

func (v *VaultClient) postJSON(ctx context.Context, addr, path string, auth bool, token string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinURL(addr, path), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return v.do(req, out)
}

func (v *VaultClient) do(req *http.Request, out any) error {
	client := v.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("vault api %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

func joinURL(addr, path string) string {
	return strings.TrimRight(addr, "/") + path
}

func trimPath(path string) string {
	return strings.TrimPrefix(strings.TrimSpace(path), "/")
}
