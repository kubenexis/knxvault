// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package eso_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kubenexis/knxvault/internal/eso"
)

func TestServerFetchWithTokenHeader(t *testing.T) {
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/secrets/kv/app/config" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"username": "admin", "password": "secret"},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer vault.Close()

	server := eso.NewServer(eso.Config{VaultAddr: vault.URL, Role: "eso-reader", AllowPlaintext: true})
	reqBody, _ := json.Marshal(eso.FetchRequest{Path: "app/config", Property: "password"})
	req := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewReader(reqBody))
	req.Header.Set("X-KNXVault-Token", "test-token")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	var resp eso.FetchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data["password"] != "secret" {
		t.Fatalf("data = %v", resp.Data)
	}
}

func TestServerFetchRequiresAuth(t *testing.T) {
	server := eso.NewServer(eso.Config{VaultAddr: "http://127.0.0.1:1", Role: "eso-reader"})
	reqBody, _ := json.Marshal(eso.FetchRequest{Path: "app/config"})
	req := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401 body=%s", rec.Code, rec.Body.String())
	}
}

// W86-05: TokenFile alone must not authenticate unless break-glass is set.
func TestServerFetchTokenFileWithoutBreakGlassUnauthorized(t *testing.T) {
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokPath, []byte("shared-proxy-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := eso.NewServer(eso.Config{
		VaultAddr: "http://127.0.0.1:1",
		Role:      "eso-reader",
		TokenFile: tokPath,
		// AllowTokenFileProxy intentionally false
	})
	reqBody, _ := json.Marshal(eso.FetchRequest{Path: "app/config"})
	req := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401 (TokenFile must not silent-proxy)", rec.Code)
	}
}

func TestServerFetchTokenFileBreakGlassOK(t *testing.T) {
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"k": "v"}})
	}))
	defer vault.Close()
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokPath, []byte("shared-proxy-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := eso.NewServer(eso.Config{
		VaultAddr:           vault.URL,
		Role:                "eso-reader",
		TokenFile:           tokPath,
		AllowTokenFileProxy: true,
	})
	reqBody, _ := json.Marshal(eso.FetchRequest{Path: "app/config"})
	req := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestListenAndServeRequiresTLS(t *testing.T) {
	s := eso.NewServer(eso.Config{})
	err := s.ListenAndServe("127.0.0.1:0")
	if err == nil {
		t.Fatal("expected TLS required error")
	}
}

func TestServerFetchConcurrentTokensIsolated(t *testing.T) {
	// Distinct tokens must not clobber each other under concurrent /fetch.
	var hits atomic.Int32
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		auth := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(auth, "Bearer ")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"who": tok},
		})
	}))
	defer vault.Close()

	server := eso.NewServer(eso.Config{VaultAddr: vault.URL, Role: "eso-reader"})
	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			want := fmt.Sprintf("tok-%d", i)
			body, _ := json.Marshal(eso.FetchRequest{Path: "app/x"})
			req := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewReader(body))
			req.Header.Set("X-KNXVault-Token", want)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				errs <- fmt.Errorf("status=%d body=%s", rec.Code, rec.Body.String())
				return
			}
			var resp eso.FetchResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				errs <- err
				return
			}
			if resp.Data["who"] != want {
				errs <- fmt.Errorf("got who=%v want %s", resp.Data["who"], want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != n {
		t.Fatalf("vault hits=%d want %d", hits.Load(), n)
	}
}

func TestServerHealth(t *testing.T) {
	server := eso.NewServer(eso.Config{})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestServerFetchMissingPath(t *testing.T) {
	server := eso.NewServer(eso.Config{})
	req := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestServerFetchRejectsPathTraversal(t *testing.T) {
	server := eso.NewServer(eso.Config{})
	body := []byte(`{"path":"../../etc/passwd"}`)
	req := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewReader(body))
	req.Header.Set("X-KNXVault-Token", "tok")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}
