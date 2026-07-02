// Package operator provides a Kubernetes operator scaffold (W30-01/02).
package operator

import (
	"context"
	"fmt"
	"os"
	"time"
)

// Reconciler syncs CRD desired state to KNXVault REST API.
type Reconciler struct {
	APIAddr string
	Token   string
}

// Run starts the operator reconcile loop stub.
func Run() error {
	r := &Reconciler{APIAddr: envOr("KNXVAULT_ADDR", "http://localhost:8200")}
	return r.Reconcile(context.Background())
}

// Reconcile performs one reconciliation pass (stub).
func (r *Reconciler) Reconcile(ctx context.Context) error {
	_ = ctx
	// W30-02: wire controller-runtime reconcile to PUT /sys/policies, POST /pki/root, etc.
	time.Sleep(10 * time.Millisecond)
	fmt.Printf("knxvault-operator: reconcile stub against %s\n", r.APIAddr)
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
