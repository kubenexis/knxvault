package handlers_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/app"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestVaultCompatKubernetesLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := testAuthService("admin")
	handler := handlers.NewVaultCompatHandler(authSvc, nil, time.Hour)

	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.POST("/v1/auth/kubernetes/login", handler.LoginKubernetes)

	body, _ := json.Marshal(map[string]string{
		"role": "app",
		"jwt":  "forged",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/kubernetes/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestVaultCompatSignPKIRequiresAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := testAuthService("admin")
	handler := handlers.NewVaultCompatHandler(authSvc, nil, time.Hour)

	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.Use(middleware.Auth(authSvc))
	r.POST("/v1/pki/sign/:role", handler.SignPKI)

	req := httptest.NewRequest(http.MethodPost, "/v1/pki/sign/web-server", bytes.NewReader([]byte(`{"common_name":"test.local"}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestVaultCompatSysHealth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := testAuthService("admin")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	seal := app.NewSealState(key)
	if !seal.Unseal(key) {
		t.Fatal("unseal")
	}
	handler := handlers.NewVaultCompatHandler(authSvc, nil, time.Hour).
		WithHealthProbe(seal, nil, "test-ver")

	r := gin.New()
	r.GET("/v1/sys/health", handler.SysHealth)

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["initialized"] != true {
		t.Fatalf("initialized = %v", body["initialized"])
	}
	if body["sealed"] != false {
		t.Fatalf("sealed = %v", body["sealed"])
	}
	if body["version"] != "test-ver" {
		t.Fatalf("version = %v", body["version"])
	}

	seal.Seal()
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("sealed status = %d", rec.Code)
	}
}

func TestVaultCompatAppRoleLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := testAuthService("admin")
	if err := authSvc.RegisterAppRole("cm-role", "cm-secret", "cert-manager", []string{"pki-admin"}); err != nil {
		t.Fatalf("RegisterAppRole: %v", err)
	}
	handler := handlers.NewVaultCompatHandler(authSvc, nil, time.Hour)

	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.POST("/v1/auth/approle/login", handler.LoginAppRole)
	r.POST("/v1/auth/:mount/login", handler.LoginMount)

	body, _ := json.Marshal(map[string]string{
		"role_id":   "cm-role",
		"secret_id": "cm-secret",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/approle/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	authBlock, ok := resp["auth"].(map[string]any)
	if !ok {
		t.Fatalf("missing auth block: %s", rec.Body.String())
	}
	if authBlock["client_token"] == "" || authBlock["client_token"] == nil {
		t.Fatal("expected client_token")
	}

	// Custom mount path via LoginMount
	body2, _ := json.Marshal(map[string]string{
		"role_id":   "cm-role",
		"secret_id": "cm-secret",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/my-approle/login", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("mount login status = %d body = %s", rec2.Code, rec2.Body.String())
	}
}

func TestVaultCompatRegisterAppRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := testAuthService("admin")
	handler := handlers.NewVaultCompatHandler(authSvc, nil, time.Hour)

	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.Use(middleware.Auth(authSvc))
	r.POST("/sys/auth/approle",
		middleware.RequirePermission(authSvc, "sys/auth", "sudo"),
		handler.RegisterAppRole,
	)

	body, _ := json.Marshal(map[string]any{
		"role_id":   "r1",
		"secret_id": "s1",
		"policies":  []string{"pki-admin"},
		"subject":   "cm",
	})
	req := httptest.NewRequest(http.MethodPost, "/sys/auth/approle", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}

	// Login with registered credentials
	loginH := handlers.NewVaultCompatHandler(authSvc, nil, time.Hour)
	r2 := gin.New()
	r2.Use(middleware.ErrorHandler())
	r2.POST("/v1/auth/approle/login", loginH.LoginAppRole)
	loginBody, _ := json.Marshal(map[string]string{"role_id": "r1", "secret_id": "s1"})
	req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/approle/login", bytes.NewReader(loginBody))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	r2.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("login status = %d body = %s", rec2.Code, rec2.Body.String())
	}
}

func TestVaultCompatSignPKIFullResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cryptoSvc, err := testCryptoService()
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	engine := pkiengine.NewEngine(cryptoSvc,
		memory.NewCARepository(),
		memory.NewRevocationRepository(),
	)
	engine.SetIssuedCertRepository(memory.NewIssuedCertRepository())
	engine.SetPKIRoleRepository(memory.NewPKIRoleRepository())
	pkiSvc := service.NewPKIService(engine, testAuditService())
	authSvc := testAuthService("admin")
	handler := handlers.NewVaultCompatHandler(authSvc, pkiSvc, time.Hour)

	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	if _, err := pkiSvc.CreateRoot(ctx, pkiengine.CreateRootRequest{
		Name:       "web-server",
		CommonName: "Web Server CA",
		TTL:        "30d",
	}); err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.Use(middleware.Auth(authSvc))
	r.POST("/v1/pki/sign/:role", middleware.RequirePermission(authSvc, "pki", "write"), handler.SignPKI)
	r.POST("/v1/:mount/sign/:role", middleware.RequirePermission(authSvc, "pki", "write"), handler.SignPKI)

	// Issue path with alt_names (cert-manager-like body without CSR)
	issueBody, _ := json.Marshal(map[string]string{
		"common_name": "demo.example.com",
		"alt_names":   "demo.example.com,www.example.com",
		"ttl":         "24h",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/pki/sign/web-server", bytes.NewReader(issueBody))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	// Also accept X-Vault-Token
	req.Header.Set("X-Vault-Token", "root-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign issue status = %d body = %s", rec.Code, rec.Body.String())
	}
	var secret map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &secret); err != nil {
		t.Fatalf("decode: %v", err)
	}
	data, ok := secret["data"].(map[string]any)
	if !ok {
		t.Fatalf("missing data: %s", rec.Body.String())
	}
	if data["certificate"] == nil || data["certificate"] == "" {
		t.Fatal("expected certificate")
	}
	if data["issuing_ca"] == nil || data["issuing_ca"] == "" {
		t.Fatal("expected issuing_ca")
	}
	if data["serial_number"] == nil {
		t.Fatal("expected serial_number")
	}

	// CSR sign path (primary cert-manager flow)
	csrPEM := mustGenerateCSR(t, "csr.example.com")
	csrBody, _ := json.Marshal(map[string]string{
		"csr":                  csrPEM,
		"common_name":          "csr.example.com",
		"alt_names":            "csr.example.com",
		"ttl":                  "12h",
		"exclude_cn_from_sans": "true",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/v1/pki_int/sign/web-server", bytes.NewReader(csrBody))
	req2.Header.Set("X-Vault-Token", "root-token")
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("csr sign status = %d body = %s", rec2.Code, rec2.Body.String())
	}
	var secret2 map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &secret2); err != nil {
		t.Fatalf("decode csr: %v", err)
	}
	data2 := secret2["data"].(map[string]any)
	if data2["certificate"] == nil || data2["certificate"] == "" {
		t.Fatal("expected CSR-signed certificate")
	}
	// CSR path must not require private_key (cert-manager already has key)
	chain, _ := data2["ca_chain"].([]any)
	if len(chain) == 0 {
		t.Fatal("expected ca_chain for CSR sign")
	}
}

func mustGenerateCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
