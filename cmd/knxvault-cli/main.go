// KNXVault CLI for Day-2 operations.
package main

import (
	"os"

	"github.com/kubenexis/knxvault/cmd/knxvault-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
