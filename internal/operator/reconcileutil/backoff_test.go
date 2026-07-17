// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package reconcileutil

import (
	"testing"
	"time"
)

func TestErrorResultBackoff(t *testing.T) {
	t.Parallel()
	r0 := ErrorResult(0)
	if r0.RequeueAfter != 5*time.Second {
		t.Fatalf("attempt0 = %v", r0.RequeueAfter)
	}
	r3 := ErrorResult(3)
	if r3.RequeueAfter != 40*time.Second {
		t.Fatalf("attempt3 = %v", r3.RequeueAfter)
	}
	r10 := ErrorResult(10)
	if r10.RequeueAfter != 5*time.Minute {
		t.Fatalf("cap = %v", r10.RequeueAfter)
	}
	// Negative attempt treated as 0.
	if ErrorResult(-1).RequeueAfter != 5*time.Second {
		t.Fatal("negative attempt")
	}
}

func TestRequeueAfter(t *testing.T) {
	t.Parallel()
	r := RequeueAfter(12 * time.Second)
	if r.RequeueAfter != 12*time.Second {
		t.Fatalf("got %v", r.RequeueAfter)
	}
}
