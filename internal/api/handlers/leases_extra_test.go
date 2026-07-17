package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/handlers"
	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestLeaseHandlerRenewTidy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	leases := memory.NewLeaseRepository()
	now := time.Now().UTC()
	_ = leases.Save(context.Background(), &domainsecrets.Lease{
		ID: "lx", Engine: "custom", RoleName: "r", Path: "p",
		TTLSeconds: 30, CreatedAt: now, ExpiresAt: now.Add(30 * time.Second), Renewable: true,
	})
	svc := service.NewLeaseService(leases, nil, nil, auditsvc.NewService(memory.NewAuditRepository()))
	h := handlers.NewLeaseHandler(svc)
	r := gin.New()
	r.POST("/sys/leases/renew", h.Renew)
	r.POST("/sys/leases/tidy", h.Tidy)

	body, _ := json.Marshal(map[string]any{"lease_id": "lx", "ttl_seconds": 90})
	req := httptest.NewRequest(http.MethodPost, "/sys/leases/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("renew status %d body %s", w.Code, w.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/sys/leases/tidy", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("tidy status %d", w2.Code)
	}
}
