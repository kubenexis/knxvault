// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestMasterKeyRotateBlockedOnMultiNodeRaft(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cs, err := crypto.NewService(key)
	if err != nil {
		t.Fatal(err)
	}
	svc := service.NewMasterKeyService(cs, nil, nil)
	svc.SetRaftRotationPolicy(true, false)
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 2)
	}
	_, err = svc.Rotate(context.Background(), service.RotateRequest{
		NewKeyBase64: base64.StdEncoding.EncodeToString(newKey),
	})
	if err == nil {
		t.Fatal("expected multi-node rotation block")
	}
	svc.SetRaftRotationPolicy(true, true)
	res, err := svc.Rotate(context.Background(), service.RotateRequest{
		NewKeyBase64: base64.StdEncoding.EncodeToString(newKey),
	})
	if err != nil || res.KeyVersion < 2 {
		t.Fatalf("allow insecure: %v %+v", err, res)
	}
}
