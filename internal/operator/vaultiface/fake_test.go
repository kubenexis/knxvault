// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package vaultiface

import (
	"context"
	"testing"
)

func TestFakeVaultLifecycle(t *testing.T) {
	t.Parallel()
	f := NewFake()
	ctx := context.Background()
	root, err := f.CreateRoot(ctx, "root", "Root", "8760h", 2048)
	if err != nil || root.ID == "" {
		t.Fatalf("%v %+v", err, root)
	}
	intm, err := f.CreateIntermediate(ctx, "root", "int", "Int", "4380h", 2048)
	if err != nil || intm.Name != "int" {
		t.Fatalf("%v %+v", err, intm)
	}
	got, err := f.GetCA(ctx, root.ID)
	if err != nil || got.Serial != root.Serial {
		t.Fatalf("%v %+v", err, got)
	}
	leaf, err := f.Issue(ctx, "root", "app.example.com", "24h", []string{"app.example.com"}, nil, 2048, false)
	if err != nil || leaf.Serial == "" {
		t.Fatalf("%v %+v", err, leaf)
	}
	rn, err := f.Renew(ctx, "ca-root", leaf.Serial, "24h")
	if err != nil || rn.CAID == "" {
		t.Fatalf("%v %+v", err, rn)
	}
	f.Fail = true
	if _, err := f.CreateRoot(ctx, "x", "x", "1h", 2048); err == nil {
		t.Fatal("expected fail")
	}
}
