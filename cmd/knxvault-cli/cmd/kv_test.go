// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"
	"testing"
)

func TestRedactKVData(t *testing.T) {
	t.Parallel()

	if got := redactKVData(nil); got != nil {
		t.Fatalf("redactKVData(nil) = %v, want nil", got)
	}

	in := map[string]any{
		"password": "s3cret",
		"host":     "db.internal",
	}
	out := redactKVData(in)
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	for key, value := range out {
		if value != RedactedValue {
			t.Fatalf("out[%q] = %v, want %q", key, value, RedactedValue)
		}
	}
	// Original map must not be mutated.
	if in["password"] != "s3cret" {
		t.Fatalf("input mutated: password = %v", in["password"])
	}
}

func TestRedactKVDataEmpty(t *testing.T) {
	t.Parallel()

	out := redactKVData(map[string]any{})
	if out == nil {
		t.Fatal("expected empty map, got nil")
	}
	if len(out) != 0 {
		t.Fatalf("len = %d, want 0", len(out))
	}
}

func TestRedactionHintConstant(t *testing.T) {
	t.Parallel()

	if RedactionHint == "" {
		t.Fatal("RedactionHint must not be empty")
	}
	if !strings.Contains(RedactionHint, "redacted") {
		t.Fatalf("RedactionHint %q must mention redacted", RedactionHint)
	}
	if !strings.Contains(RedactionHint, "--show-secrets") {
		t.Fatalf("RedactionHint %q must mention --show-secrets", RedactionHint)
	}
	if RedactedValue != "[REDACTED]" {
		t.Fatalf("RedactedValue = %q", RedactedValue)
	}
}
