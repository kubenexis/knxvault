// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package eso_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	server := eso.NewServer(eso.Config{VaultAddr: vault.URL, Role: "eso-reader"})
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
