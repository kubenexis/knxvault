// KNXVault is a lightweight secrets management and PKI system.
package main

import (
	"fmt"
	"net/http"
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
	host := addr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + host + "/health")
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
