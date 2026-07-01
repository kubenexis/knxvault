package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubenexis/knxvault/pkg/client"
)

func TestHealthAndKV(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "version": "test"})
		case "/secrets/kv/app/db":
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Fatalf("missing auth header")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"password": "x"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := client.New(srv.URL, "tok")
	health, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() = %v", err)
	}
	if health.Status != "healthy" {
		t.Fatalf("status = %q", health.Status)
	}

	resp, err := c.KVGet(context.Background(), "app/db")
	if err != nil {
		t.Fatalf("KVGet() = %v", err)
	}
	if resp.Data["password"] != "x" {
		t.Fatalf("data = %+v", resp.Data)
	}
}

func TestReadyAndLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":     "ready",
				"version":    "test",
				"ha_enabled": true,
				"leader":     true,
			})
		case "/auth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_token": "session-token",
				"ttl":          3600,
				"policies":     []string{"admin"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := client.New(srv.URL, "")
	ready, err := c.Ready(context.Background())
	if err != nil {
		t.Fatalf("Ready() = %v", err)
	}
	if !ready.HAEnabled || ready.Leader == nil || !*ready.Leader {
		t.Fatalf("ready = %+v", ready)
	}

	login, err := c.LoginToken(context.Background(), "bootstrap")
	if err != nil {
		t.Fatalf("LoginToken() = %v", err)
	}
	if login.ClientToken != "session-token" {
		t.Fatalf("token = %q", login.ClientToken)
	}
	if c.Token != "session-token" {
		t.Fatalf("client token = %q", c.Token)
	}
}

func TestK8sLoginAndKVPut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/kubernetes":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_token": "k8s-token",
				"ttl":          1800,
				"policies":     []string{"app"},
			})
		case "/secrets/kv/app/config":
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := client.New(srv.URL, "")
	login, err := c.LoginKubernetes(context.Background(), "app", "jwt")
	if err != nil {
		t.Fatalf("LoginKubernetes() = %v", err)
	}
	if login.ClientToken != "k8s-token" {
		t.Fatalf("token = %q", login.ClientToken)
	}
	if err := c.KVPut(context.Background(), "app/config", map[string]any{"key": "val"}); err != nil {
		t.Fatalf("KVPut() = %v", err)
	}
}

func TestPKIIssueAndBackup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pki/issue":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"cert_pem":        "CERT",
				"private_key_pem": "KEY",
				"serial":          "01",
				"expires_at":      "2030-01-01T00:00:00Z",
			})
		case "/sys/backup":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"format": "knxvault-backup",
				"data":   "YmFja3Vw",
			})
		case "/sys/restore":
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := client.New(srv.URL, "admin-token")
	issue, err := c.PKIIssue(context.Background(), client.IssueCertRequest{
		Role:       "web",
		CommonName: "example.com",
	})
	if err != nil {
		t.Fatalf("PKIIssue() = %v", err)
	}
	if issue.CertPEM != "CERT" {
		t.Fatalf("cert = %q", issue.CertPEM)
	}

	backup, err := c.BackupCreate(context.Background(), client.BackupCreateRequest{})
	if err != nil {
		t.Fatalf("BackupCreate() = %v", err)
	}
	if backup.Format != "knxvault-backup" {
		t.Fatalf("format = %q", backup.Format)
	}
	if err := c.BackupRestore(context.Background(), []byte("archive")); err != nil {
		t.Fatalf("BackupRestore() = %v", err)
	}
}

func TestAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error_code": "forbidden",
			"message":    "denied",
		})
	}))
	defer srv.Close()

	c := client.New(srv.URL, "tok")
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*client.APIError)
	if !ok {
		t.Fatalf("err type = %T", err)
	}
	if apiErr.Status != http.StatusForbidden || apiErr.Code != "forbidden" {
		t.Fatalf("apiErr = %+v", apiErr)
	}
}

func TestKVGetEscapesPathSegments(t *testing.T) {
	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
	}))
	defer srv.Close()

	c := client.New(srv.URL, "tok")
	c.HTTP = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		return http.DefaultTransport.RoundTrip(req)
	})}
	if _, err := c.KVGet(context.Background(), "app/db creds"); err != nil {
		t.Fatalf("KVGet() = %v", err)
	}
	if !strings.Contains(gotURL, "app%2Fdb%20creds") {
		t.Fatalf("url = %q, want escaped path segment", gotURL)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestNewDefaults(t *testing.T) {
	c := client.New("", "")
	if c.BaseURL != "http://localhost:8200" {
		t.Fatalf("base URL = %q", c.BaseURL)
	}
	if c.HTTP == nil {
		t.Fatal("expected default HTTP client")
	}
}
