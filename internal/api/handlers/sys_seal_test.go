package handlers_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/app"
	"github.com/kubenexis/knxvault/internal/netutil"
)

func TestSysHandlerSealAndUnseal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	seal := app.NewSealState(key)
	authSvc := testAuthService("admin")
	handler := handlers.NewSysHandler(authSvc, nil, nil, nil, nil, nil, seal, nil, nil, false, nil)

	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.POST("/sys/seal", middleware.Auth(authSvc), handler.Seal)
	r.POST("/sys/unseal", handler.Unseal)

	sealReq := httptest.NewRequest(http.MethodPost, "/sys/seal", nil)
	sealReq.Header.Set("Authorization", "Bearer root-token")
	sealRec := httptest.NewRecorder()
	r.ServeHTTP(sealRec, sealReq)
	if sealRec.Code != http.StatusOK {
		t.Fatalf("seal status = %d body=%s", sealRec.Code, sealRec.Body.String())
	}
	if !seal.Sealed() {
		t.Fatal("expected sealed")
	}

	body, _ := json.Marshal(map[string]string{"key": base64.StdEncoding.EncodeToString(key)})
	unsealReq := httptest.NewRequest(http.MethodPost, "/sys/unseal", bytes.NewReader(body))
	unsealReq.Header.Set("Content-Type", "application/json")
	unsealRec := httptest.NewRecorder()
	r.ServeHTTP(unsealRec, unsealReq)
	if unsealRec.Code != http.StatusOK {
		t.Fatalf("unseal status = %d body=%s", unsealRec.Code, unsealRec.Body.String())
	}
	if seal.Sealed() {
		t.Fatal("expected unsealed")
	}
}

func TestSysHandlerUnsealRejectsInvalidKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := make([]byte, 32)
	seal := app.NewSealState(key)
	seal.Seal()
	handler := handlers.NewSysHandler(testAuthService("admin"), nil, nil, nil, nil, nil, seal, nil, nil, false, nil)

	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.POST("/sys/unseal", handler.Unseal)

	wrong := make([]byte, 32)
	for i := range wrong {
		wrong[i] = 0xFF
	}
	body, _ := json.Marshal(map[string]string{"key": base64.StdEncoding.EncodeToString(wrong)})
	req := httptest.NewRequest(http.MethodPost, "/sys/unseal", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if !seal.Sealed() {
		t.Fatal("expected still sealed after bad unseal")
	}
}

func TestSysHandlerUnsealSourceAllowlist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	seal := app.NewSealState(key)
	seal.Seal()
	handler := handlers.NewSysHandler(testAuthService("admin"), nil, nil, nil, nil, nil, seal, nil, nil, false, nil)
	nets, err := netutil.ParseCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	handler.SetUnsealAllowNets(nets)

	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.POST("/sys/unseal", handler.Unseal)

	body, _ := json.Marshal(map[string]string{"key": base64.StdEncoding.EncodeToString(key)})

	// Denied: client outside allowlist (default test remote is 192.0.2.1 / ::1 depending on gin).
	req := httptest.NewRequest(http.MethodPost, "/sys/unseal", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.10:1234"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("expected deny from public IP, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !seal.Sealed() {
		t.Fatal("expected still sealed after denied unseal")
	}

	// Allowed: private range in allowlist.
	req2 := httptest.NewRequest(http.MethodPost, "/sys/unseal", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.RemoteAddr = "10.1.2.3:9999"
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected allow from 10.0.0.0/8, got %d body=%s", rec2.Code, rec2.Body.String())
	}
	if seal.Sealed() {
		t.Fatal("expected unsealed after allowed source")
	}
}
