// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

func TestSecretVersionValidate(t *testing.T) {
	sv := &secrets.SecretVersion{
		ID:        uuid.New(),
		Path:      "app/db",
		Version:   1,
		DataEnc:   []byte{1},
		DEKEnc:    []byte{2},
		CreatedAt: time.Now().UTC(),
	}
	if err := sv.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestSecretVersionRejectsEmptyPath(t *testing.T) {
	sv := &secrets.SecretVersion{
		ID:      uuid.New(),
		Version: 1,
		DataEnc: []byte{1},
		DEKEnc:  []byte{2},
	}
	if err := sv.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}
