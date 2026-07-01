// knxvault-eso is an External Secrets Operator webhook adapter for KNXVault (W40-01).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kubenexis/knxvault/internal/version"
	"github.com/kubenexis/knxvault/pkg/client"
)

type fetchRequest struct {
	Path     string `json:"path"`
	Property string `json:"property"`
	Role     string `json:"role"`
}

type fetchResponse struct {
	Data map[string]any `json:"data"`
}

func main() {
	version.AnnounceStandard("knxvault-eso")
	addr := envOr("KNXVAULT_ESO_ADDR", ":8080")
	vaultAddr := envOr("KNXVAULT_ADDR", "http://knxvault:8200")
	role := envOr("KNXVAULT_ROLE", "eso-reader")
	tokenPath := envOr("K8S_SA_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req fetchRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if req.Path == "" {
			http.Error(w, "path is required", http.StatusBadRequest)
			return
		}
		if req.Role == "" {
			req.Role = role
		}

		saToken, err := os.ReadFile(tokenPath)
		if err != nil {
			http.Error(w, "read service account token", http.StatusInternalServerError)
			return
		}
		c := client.New(vaultAddr, "")
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if _, err := c.LoginKubernetes(ctx, req.Role, strings.TrimSpace(string(saToken))); err != nil {
			http.Error(w, fmt.Sprintf("kubernetes login: %v", err), http.StatusUnauthorized)
			return
		}
		secret, err := c.KVGet(ctx, req.Path)
		if err != nil {
			http.Error(w, fmt.Sprintf("kv get: %v", err), http.StatusBadGateway)
			return
		}
		data := secret.Data
		if req.Property != "" {
			value, ok := data[req.Property]
			if !ok {
				http.Error(w, fmt.Sprintf("property %q not found in secret", req.Property), http.StatusNotFound)
				return
			}
			data = map[string]any{req.Property: value}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fetchResponse{Data: data})
	})

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	log.Printf("knxvault-eso listening on %s (vault=%s role=%s)", addr, vaultAddr, role)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}