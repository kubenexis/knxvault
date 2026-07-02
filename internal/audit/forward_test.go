package audit_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestServiceForwardsAuditEntryToSIEM(t *testing.T) {
	var (
		mu    sync.Mutex
		got   map[string]any
		calls int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() = %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		calls++
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	repo := memory.NewAuditRepository()
	svc := audit.NewService(repo)
	svc.SetForwardURL(server.URL)

	ctx := context.Background()
	if err := svc.Record(ctx, "siem-actor", "sys.seal", "sys/seal", "success", map[string]any{"sealed": true}); err != nil {
		t.Fatalf("Record() = %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := calls
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for SIEM forward")
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if got["actor"] != "siem-actor" || got["action"] != "sys.seal" {
		t.Fatalf("forwarded payload = %#v", got)
	}
	if got["resource"] != "sys/seal" || got["status"] != "success" {
		t.Fatalf("forwarded payload = %#v", got)
	}
	if got["hash"] == "" || got["hash"] == nil {
		t.Fatalf("expected hash in forwarded entry: %#v", got)
	}
}
