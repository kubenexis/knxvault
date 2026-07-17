// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/engine/transit"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestTransitServiceRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	cs, err := crypto.NewService(key)
	if err != nil {
		t.Fatal(err)
	}
	eng := transit.NewEngine(memory.NewSecretRepository(), cs)
	svc := service.NewTransitService(eng, auditsvc.NewService(memory.NewAuditRepository()))
	ctx := context.Background()
	if _, err := svc.CreateKey(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	ct, err := svc.Encrypt(ctx, "k1", "hello-world", 0)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := svc.Decrypt(ctx, "k1", ct)
	if err != nil || pt != "hello-world" {
		t.Fatalf("decrypt: %v %q", err, pt)
	}
}
