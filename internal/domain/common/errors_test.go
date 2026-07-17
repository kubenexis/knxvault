// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package common_test

import (
	"errors"
	"testing"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

func TestNewAndError(t *testing.T) {
	err := common.New(common.ErrCodeNotFound, "missing")
	if err.Code != common.ErrCodeNotFound || err.Message != "missing" {
		t.Fatalf("unexpected error: %+v", err)
	}
	if err.Error() != "missing" {
		t.Fatalf("Error() = %q", err.Error())
	}
	if err.Unwrap() != nil {
		t.Fatal("expected nil cause")
	}
}

func TestWrapUnwrap(t *testing.T) {
	cause := errors.New("root")
	err := common.Wrap(common.ErrCodeInternal, "boom", cause)
	if err.Error() != "boom: root" {
		t.Fatalf("Error() = %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatal("expected errors.Is to find cause")
	}
	var kv *common.KNXVaultError
	if !errors.As(err, &kv) || kv.Code != common.ErrCodeInternal {
		t.Fatalf("errors.As failed: %+v", kv)
	}
}
