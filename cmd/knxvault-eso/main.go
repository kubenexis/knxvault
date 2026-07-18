// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// knxvault-eso is an External Secrets Operator webhook adapter for KNXVault.
package main

import (
	"log"
	"os"
	"strings"

	"github.com/kubenexis/knxvault/internal/eso"
	"github.com/kubenexis/knxvault/internal/version"
)

func main() {
	if version.HandleArgs(os.Args[1:]) {
		return
	}
	version.AnnounceStandard("knxvault-eso")

	addr := envOr("KNXVAULT_ESO_ADDR", ":8443")
	// Default vault URL prefers HTTPS (align with W86-22 posture for edge clients).
	cfg := eso.Config{
		VaultAddr:           envOr("KNXVAULT_ADDR", "https://localhost:8200"),
		Role:                envOr("KNXVAULT_ESO_ROLE", "eso-reader"),
		TokenFile:           os.Getenv("KNXVAULT_TOKEN_FILE"),
		AllowInsecureSAAuth: strings.EqualFold(os.Getenv("KNXVAULT_ESO_ALLOW_INSECURE_SA_AUTH"), "true"),
		AllowTokenFileProxy: strings.EqualFold(os.Getenv("KNXVAULT_ESO_ALLOW_TOKEN_FILE_PROXY"), "true"),
		TLSCertFile:         os.Getenv("KNXVAULT_ESO_TLS_CERT_FILE"),
		TLSKeyFile:          os.Getenv("KNXVAULT_ESO_TLS_KEY_FILE"),
		AllowPlaintext:      strings.EqualFold(os.Getenv("KNXVAULT_ESO_ALLOW_PLAINTEXT"), "true"),
	}
	server := eso.NewServer(cfg)
	log.Printf("knxvault-eso listening on %s (vault=%s role=%s tls=%v)", addr, cfg.VaultAddr, cfg.Role,
		cfg.TLSCertFile != "" && cfg.TLSKeyFile != "")
	if err := server.ListenAndServe(addr); err != nil {
		log.Fatalf("knxvault-eso: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
