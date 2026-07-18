// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package eso provides an External Secrets Operator webhook adapter for KNXVault.
package eso

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kubenexis/knxvault/pkg/client"
)

// FetchRequest is the webhook payload from External Secrets Operator.
type FetchRequest struct {
	Path     string `json:"path"`
	Property string `json:"property"`
	Role     string `json:"role"`
}

// FetchResponse is returned to ESO webhook provider jsonPath "$.data".
type FetchResponse struct {
	Data map[string]any `json:"data"`
}

// Config configures the ESO adapter server.
type Config struct {
	VaultAddr string
	Role      string
	// TokenFile is only used when AllowTokenFileProxy is true (explicit break-glass).
	// Env: KNXVAULT_TOKEN_FILE + KNXVAULT_ESO_ALLOW_TOKEN_FILE_PROXY=true (W86-05).
	TokenFile string
	// AllowInsecureSAAuth enables SA JWT login when the request has no caller token.
	// Default false — unauthenticated callers must not obtain secrets.
	AllowInsecureSAAuth bool
	// AllowTokenFileProxy when true allows TokenFile as the sole credential without
	// a per-request header (shared proxy). Default false (W86-05).
	AllowTokenFileProxy bool
	// TLSCertFile / TLSKeyFile enable HTTPS listen (W86-04). Required unless AllowPlaintext.
	TLSCertFile string
	TLSKeyFile  string
	// AllowPlaintext permits HTTP listen without TLS (lab only). Default false.
	// Env: KNXVAULT_ESO_ALLOW_PLAINTEXT=true
	AllowPlaintext bool
}

// Server serves ESO webhook fetch requests.
type Server struct {
	cfg    Config
	client *client.Client
}

// NewServer constructs an ESO adapter server.
func NewServer(cfg Config) *Server {
	if cfg.Role == "" {
		cfg.Role = "eso-reader"
	}
	return &Server{cfg: cfg, client: client.New(cfg.VaultAddr, "")}
}

// Handler returns the HTTP handler for the adapter.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/fetch", s.handleFetch)
	mux.HandleFunc("/v1/fetch", s.handleFetch)
	return mux
}

// ListenAndServe starts the adapter with TLS by default (W86-04).
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	certFile := strings.TrimSpace(s.cfg.TLSCertFile)
	keyFile := strings.TrimSpace(s.cfg.TLSKeyFile)
	if certFile == "" || keyFile == "" {
		if !s.cfg.AllowPlaintext {
			return fmt.Errorf("TLS required: set KNXVAULT_ESO_TLS_CERT_FILE and KNXVAULT_ESO_TLS_KEY_FILE (or KNXVAULT_ESO_ALLOW_PLAINTEXT=true for lab only)")
		}
		return srv.ListenAndServe()
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return fmt.Errorf("load ESO TLS cert: %w", err)
	}
	return srv.ListenAndServeTLS(certFile, keyFile)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req FetchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}
	// Path traversal / absolute path rejection (same policy as vault KV admin paths).
	if err := validateESOPath(req.Path); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	role := req.Role
	if role == "" {
		role = s.cfg.Role
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	token, err := s.resolveToken(ctx, role, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	s.client.Token = token

	secret, err := s.client.KVGet(ctx, req.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	data := secret.Data
	if req.Property != "" {
		value, ok := data[req.Property]
		if !ok {
			http.Error(w, fmt.Sprintf("property %q not found", req.Property), http.StatusNotFound)
			return
		}
		data = map[string]any{req.Property: value}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(FetchResponse{Data: data})
}

func validateESOPath(path string) error {
	p := strings.TrimSpace(path)
	if p == "" {
		return fmt.Errorf("path is required")
	}
	if strings.Contains(p, "..") || strings.HasPrefix(p, "/") {
		return fmt.Errorf("path must be a relative KV path without .. segments")
	}
	return nil
}

func (s *Server) resolveToken(ctx context.Context, role string, r *http.Request) (string, error) {
	// Per-request caller identity preferred (W86-05).
	if token := strings.TrimSpace(r.Header.Get("X-KNXVault-Token")); token != "" {
		return token, nil
	}
	if token := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(token), "bearer ") {
		return strings.TrimSpace(token[7:]), nil
	}
	// TokenFile is a shared proxy — only when explicitly break-glassed (W86-05).
	if s.cfg.AllowTokenFileProxy && s.cfg.TokenFile != "" {
		raw, err := os.ReadFile(s.cfg.TokenFile)
		if err == nil {
			if token := strings.TrimSpace(string(raw)); token != "" {
				return token, nil
			}
		}
	}
	// SA auto-login is opt-in only (W50-01 / W86-05). Unauthenticated network peers must not
	// force the adapter to mint a vault token with the pod identity.
	if !s.cfg.AllowInsecureSAAuth {
		return "", fmt.Errorf("missing authentication: provide X-KNXVault-Token or Authorization Bearer (TokenFile proxy and SA auto-login disabled unless explicitly enabled)")
	}
	jwtPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if raw, err := os.ReadFile(jwtPath); err == nil {
		jwt := strings.TrimSpace(string(raw))
		if jwt != "" {
			resp, err := s.client.LoginKubernetes(ctx, role, jwt)
			if err != nil {
				return "", err
			}
			return resp.ClientToken, nil
		}
	}
	return "", fmt.Errorf("no authentication token available")
}
