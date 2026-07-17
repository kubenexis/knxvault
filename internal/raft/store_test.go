// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/audit"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

func TestLookupRejectsWriteCommand(t *testing.T) {
	store := NewStore()
	payload, err := json.Marshal(audit.Entry{
		Action: "test",
		Status: "success",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	resp, err := store.Lookup(Command{Op: OpAuditAppend, Payload: payload})
	if err != nil {
		t.Fatalf("Lookup(write) = %v", err)
	}
	var writeResp Response
	if err := json.Unmarshal(resp, &writeResp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if writeResp.ErrorCode != "validation_error" {
		t.Fatalf("expected validation_error, got %+v", writeResp)
	}

	resp, err = store.Lookup(Command{Op: OpAuditLatestHash})
	if err != nil {
		t.Fatalf("Lookup(read) = %v", err)
	}
	var decoded Response
	if err := json.Unmarshal(resp, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.ErrorCode != "" {
		t.Fatalf("unexpected error: %+v", decoded)
	}
}

func TestConcurrentSecretPutAtomic(t *testing.T) {
	store := NewStore()
	path := "app/config"
	const workers = 10

	var wg sync.WaitGroup
	versions := make(chan int, workers)
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload, err := json.Marshal(struct {
				SecretVersion secrets.SecretVersion
				CasVersion    *int
				MaxVersions   int
			}{
				SecretVersion: secrets.SecretVersion{
					ID:        uuid.New(),
					Path:      path,
					DataEnc:   []byte{byte(i + 1)},
					DEKEnc:    []byte("dek"),
					CreatedAt: time.Now().UTC(),
				},
				MaxVersions: 10,
			})
			if err != nil {
				errs <- err
				return
			}
			resp, err := store.Handle(Command{Op: OpSecretPut, Payload: payload})
			if err != nil {
				errs <- err
				return
			}
			var version int
			if err := DecodeResult(resp, &version); err != nil {
				errs <- err
				return
			}
			versions <- version
		}(i)
	}

	wg.Wait()
	close(versions)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("put failed: %v", err)
		}
	}

	seen := make(map[int]struct{})
	for v := range versions {
		if v < 1 {
			t.Fatalf("invalid version %d", v)
		}
		if _, dup := seen[v]; dup {
			t.Fatalf("duplicate version %d", v)
		}
		seen[v] = struct{}{}
	}
	if len(seen) != workers {
		t.Fatalf("expected %d unique versions, got %d", workers, len(seen))
	}
}
