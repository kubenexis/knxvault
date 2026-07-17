// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/infra/k8s"
)

func TestInClusterConfigAvailable(t *testing.T) {
	_ = k8s.InClusterConfigAvailable()
}

func TestLeaderElectorAcquiresLease(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("test-token"), 0o600); err != nil {
		t.Fatalf("WriteFile() = %v", err)
	}

	var getCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.Method {
		case http.MethodGet:
			getCount++
			http.NotFound(w, r)
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("method = %s", r.Method)
		}
	}))
	defer srv.Close()

	elector, err := k8s.NewLeaderElector(k8s.LeaderConfig{
		Namespace: "test-ns",
		LeaseName: "test-lease",
		Identity:  "node-1",
		APIHost:   srv.URL,
		TokenPath: tokenFile,
	})
	if err != nil {
		t.Fatalf("NewLeaderElector() = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	leadership := make(chan struct{}, 1)
	err = elector.Run(ctx, func(ctx context.Context) {
		leadership <- struct{}{}
		<-ctx.Done()
	})
	if err != context.Canceled && err != context.DeadlineExceeded {
		t.Fatalf("Run() = %v", err)
	}
	if getCount == 0 {
		t.Fatal("expected lease GET attempts")
	}
	select {
	case <-leadership:
	default:
		t.Fatal("expected leadership callback")
	}
}

func TestNewLeaderElectorRequiresToken(t *testing.T) {
	_, err := k8s.NewLeaderElector(k8s.LeaderConfig{
		TokenPath: filepath.Join(t.TempDir(), "missing"),
	})
	if err == nil {
		t.Fatal("expected error for missing token file")
	}
}
