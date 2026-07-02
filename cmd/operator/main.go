// KNXVault Kubernetes operator scaffold (W30-01/02).
package main

import (
	"fmt"
	"os"

	"github.com/kubenexis/knxvault/internal/operator"
)

func main() {
	if err := operator.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "operator error: %v\n", err)
		os.Exit(1)
	}
}
