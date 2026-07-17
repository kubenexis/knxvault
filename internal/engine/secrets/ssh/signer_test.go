// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"testing"
	"time"
)

func TestCertEpochSecondsRejectsPreEpoch(t *testing.T) {
	_, err := certEpochSeconds(time.Unix(-1, 0))
	if err == nil {
		t.Fatal("expected error for pre-epoch certificate time")
	}
}

func TestCertEpochSecondsAcceptsValidTime(t *testing.T) {
	ts := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	got, err := certEpochSeconds(ts)
	if err != nil {
		t.Fatalf("certEpochSeconds() = %v", err)
	}
	if got != uint64(ts.Unix()) {
		t.Fatalf("got %d, want %d", got, ts.Unix())
	}
}
