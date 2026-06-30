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
)

func TestSysHandlerSealAndUnseal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	seal := app.NewSealState(key)
	authSvc := testAuthService("admin")
	handler := handlers.NewSysHandler(authSvc, nil, nil, nil, nil, seal, nil, nil, false, nil)

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
