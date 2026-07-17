// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// knxvault-csi is the Secrets Store CSI Driver provider for KNXVault.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubenexis/knxvault/internal/inject/csi"
	"github.com/kubenexis/knxvault/internal/version"
)

func main() {
	if version.HandleArgs(os.Args[1:]) {
		return
	}
	version.AnnounceStandard("knxvault-csi")

	socket := os.Getenv("KNXVAULT_CSI_SOCKET")
	if socket == "" {
		socket = "/var/run/secrets-store-csi-providers/knxvault.sock"
	}
	server := csi.NewServer(csi.NewVaultClient())
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("knxvault-csi listening on %s", socket)
	if err := server.Serve(ctx, socket); err != nil && err != context.Canceled {
		log.Fatalf("csi provider: %v", err)
	}
}
