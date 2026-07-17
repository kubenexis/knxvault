package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestPKIHandlerCreateRootAndIssue(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cryptoSvc, err := testCryptoService()
	if err != nil {
		t.Fatalf("testCryptoService() = %v", err)
	}
	engine := pkiengine.NewEngine(cryptoSvc,
		memory.NewCARepository(),
		memory.NewRevocationRepository(),
	)
	engine.SetIssuedCertRepository(memory.NewIssuedCertRepository())
	engine.SetPKIRoleRepository(memory.NewPKIRoleRepository())
	pkiSvc := service.NewPKIService(engine, testAuditService())
	handler := handlers.NewPKIHandler(pkiSvc)
	authSvc := testAuthService("pki-admin")

	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.POST("/pki/root", middleware.RequirePermission(authSvc, "pki", "write"), handler.CreateRoot)
	r.POST("/pki/issue", middleware.RequirePermission(authSvc, "pki", "write"), handler.Issue)
	r.GET("/pki/ca/:id", middleware.RequirePermission(authSvc, "pki", "read"), handler.GetCA)
	r.GET("/pki/ca/:id/export", middleware.RequirePermission(authSvc, "pki", "read"), handler.ExportCA)

	rootBody, _ := json.Marshal(dto.CreateRootCARequest{
		Name:       "api-root",
		CommonName: "API Root CA",
		TTL:        "30d",
	})
	req := httptest.NewRequest(http.MethodPost, "/pki/root", bytes.NewReader(rootBody))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create root status = %d body = %s", rec.Code, rec.Body.String())
	}
	var root dto.CAResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &root); err != nil {
		t.Fatalf("decode root: %v", err)
	}
	if root.ID == "" {
		t.Fatal("expected CA id")
	}

	issueBody, _ := json.Marshal(dto.IssueCertRequest{
		Role:       "api-root",
		CommonName: "svc.example.com",
		DNSNames:   []string{"svc.example.com"},
		TTL:        "7d",
	})
	req = httptest.NewRequest(http.MethodPost, "/pki/issue", bytes.NewReader(issueBody))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/pki/ca/"+root.ID, nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get ca status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/pki/ca/"+root.ID+"/export", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export status = %d body = %s", rec.Code, rec.Body.String())
	}
}
