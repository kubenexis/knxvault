package middleware_test

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
	"github.com/kubenexis/knxvault/internal/auth"
)

func TestAuthLoginThrottleReturns429(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := middleware.NewRateLimiter(2, true)
	authSvc := auth.NewService(auth.NewTokenStore(0), auth.NewRBAC(), "")
	authSvc.SetK8sLoginOptions(auth.K8sLoginOptions{RaftEnabled: true})
	handler := handlers.NewAuthHandler(authSvc, 0)

	r := gin.New()
	r.Use(middleware.AuthLoginThrottle(limiter), middleware.ErrorHandler())
	r.POST("/auth/kubernetes", handler.LoginKubernetes)

	body, _ := json.Marshal(dto.K8sLoginRequest{Role: "app", JWT: "bad"})
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/kubernetes", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "10.0.0.9:1234"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if i < 2 && rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d throttled early: %d", i, rec.Code)
		}
		if i == 2 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("request 3 status = %d, want 429 body = %s", rec.Code, rec.Body.String())
		}
	}
}
