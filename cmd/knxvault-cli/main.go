// KNXVault CLI for Day-2 operations.
package main

import (
	"os"

	"github.com/kubenexis/knxvault/cmd/knxvault-cli/cmd"
	"github.com/kubenexis/knxvault/internal/version"
)

func main() {
	if version.HandleArgs(os.Args[1:]) {
		return
	}
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
