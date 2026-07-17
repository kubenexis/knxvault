// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package raft_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/pki"
)

func testRootCA(name string) *pki.CA {
	return &pki.CA{
		ID:            uuid.New(),
		Name:          name,
		Type:          pki.CATypeRoot,
		Serial:        "01",
		CertPEM:       "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		PrivateKeyEnc: []byte{1, 2, 3},
		DEKEnc:        []byte{4, 5, 6},
		Status:        pki.CAStatusActive,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour),
	}
}

func mustCommand(t *testing.T, op string, payload any) []byte {
	t.Helper()
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		raw = b
	}
	out, err := json.Marshal(struct {
		Op      string          `json:"op"`
		Payload json.RawMessage `json:"payload,omitempty"`
	}{Op: op, Payload: raw})
	if err != nil {
		t.Fatalf("marshal command: %v", err)
	}
	return out
}

func mustPayload(t *testing.T, payload any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
