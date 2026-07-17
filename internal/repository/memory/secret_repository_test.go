// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestSecretRepositoryUpdateDEKEnc(t *testing.T) {
	repo := memory.NewSecretRepository()
	ctx := context.Background()
	sv := &secrets.SecretVersion{
		ID:        uuid.New(),
		Path:      "app/db",
		Version:   1,
		DataEnc:   []byte{1, 2, 3},
		DEKEnc:    []byte{9, 9, 9},
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.SaveVersion(ctx, sv); err != nil {
		t.Fatalf("SaveVersion() = %v", err)
	}
	newDEK := []byte{7, 7, 7, 7}
	if err := repo.UpdateDEKEnc(ctx, "app/db", 1, newDEK); err != nil {
		t.Fatalf("UpdateDEKEnc() = %v", err)
	}
	got, err := repo.GetVersion(ctx, "app/db", 1)
	if err != nil {
		t.Fatalf("GetVersion() = %v", err)
	}
	if string(got.DEKEnc) != string(newDEK) {
		t.Fatalf("DEKEnc = %v, want %v", got.DEKEnc, newDEK)
	}
}
