// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// KNXVault is a lightweight secrets management and PKI system.
package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kubenexis/knxvault/cmd/knxvault/cmd"
	"github.com/kubenexis/knxvault/internal/version"
)

func main() {
	if version.HandleArgs(os.Args[1:]) {
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		os.Exit(runHealthcheck())
	}

	if err := cmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runHealthcheck() int {
	addr := os.Getenv("KNXVAULT_HTTP_ADDR")
	if addr == "" {
		addr = ":8200"
	}
	port, err := localHealthPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}

	u := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort("127.0.0.1", port),
		Path:   "/health",
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

// localHealthPort extracts the listen port from KNXVAULT_HTTP_ADDR for loopback probes.
// The bind address host is ignored so a mis-set value cannot steer the healthcheck elsewhere.
func localHealthPort(addr string) (string, error) {
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid KNXVAULT_HTTP_ADDR %q: %w", addr, err)
	}
	return port, nil
}
