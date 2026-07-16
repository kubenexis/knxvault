// KNXVault Kubernetes operator (W30-01–W30-10).
// Reconciles CA, Issuer, Certificate, CertificateRequest CRDs and optional Ingress shim
// so clusters can use KNXVault PKI without cert-manager.
package main

import (
	"fmt"
	"os"

	"github.com/kubenexis/knxvault/internal/operator"
)

func main() {
	if err := operator.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "knxvault-operator: %v\n", err)
		os.Exit(1)
	}
}
