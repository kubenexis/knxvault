// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// knxvault-eso is an External Secrets Operator webhook adapter for KNXVault.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/kubenexis/knxvault/internal/eso"
	"github.com/kubenexis/knxvault/internal/version"
)

func main() {
	if version.HandleArgs(os.Args[1:]) {
		return
	}
	version.AnnounceStandard("knxvault-eso")

	addr := envOr("KNXVAULT_ESO_ADDR", ":8080")
	cfg := eso.Config{
		VaultAddr: envOr("KNXVAULT_ADDR", "http://localhost:8200"),
		Role:      envOr("KNXVAULT_ESO_ROLE", "eso-reader"),
		TokenFile: os.Getenv("KNXVAULT_TOKEN_FILE"),
	}
	server := eso.NewServer(cfg)
	log.Printf("knxvault-eso listening on %s (vault=%s role=%s)", addr, cfg.VaultAddr, cfg.Role)
	if err := http.ListenAndServe(addr, server.Handler()); err != nil {
		log.Fatalf("knxvault-eso: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
