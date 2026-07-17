// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
)

// recordingSecretRepo captures the last SaveVersion call to assert encrypt-before-persist.
type recordingSecretRepo struct {
	repository.SecretRepository
	saved *domainsecrets.SecretVersion
}

func (r *recordingSecretRepo) SaveVersion(_ context.Context, sv *domainsecrets.SecretVersion) error {
	cp := *sv
	r.saved = &cp
	return nil
}

func (r *recordingSecretRepo) NextVersion(context.Context, string) (int, error) {
	return 1, nil
}

func (r *recordingSecretRepo) PutAtomic(_ context.Context, sv *domainsecrets.SecretVersion, _ *int, _ int) (int, error) {
	sv.Version = 1
	if err := r.SaveVersion(context.Background(), sv); err != nil {
		return 0, err
	}
	return sv.Version, nil
}

func TestKVV2PutEncryptsBeforePersist(t *testing.T) {
	key := make([]byte, 32)
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	repo := &recordingSecretRepo{SecretRepository: nil}
	engine := secretsengine.NewKVV2Engine(repo, cryptoSvc)

	plaintext := map[string]any{"password": "s3cret"}
	_, err = engine.Put(context.Background(), "app/db", plaintext, secretsengine.PutOptions{})
	if err != nil {
		t.Fatalf("Put() = %v", err)
	}
	if repo.saved == nil {
		t.Fatal("expected SaveVersion to be called")
	}

	raw, err := json.Marshal(plaintext)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(repo.saved.DataEnc, raw) || bytes.Contains(repo.saved.DataEnc, []byte("s3cret")) {
		t.Fatal("DataEnc must not contain plaintext secret")
	}
	if len(repo.saved.DEKEnc) == 0 {
		t.Fatal("DEKEnc must be set")
	}

	opened, err := cryptoSvc.Open(repo.saved.DataEnc, repo.saved.DEKEnc)
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	if !bytes.Equal(opened, raw) {
		t.Fatalf("decrypted payload mismatch: %s", opened)
	}
}
