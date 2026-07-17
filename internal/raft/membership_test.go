// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"context"
	"strings"
	"testing"
)

func TestAddNodeValidation(t *testing.T) {
	ctx := context.Background()

	var nilClient *Client
	if err := nilClient.AddNode(ctx, 2, "host:63001"); err == nil {
		t.Fatal("expected error for nil client")
	}

	client := &Client{nodeID: 1}
	if err := client.AddNode(ctx, 0, "host:63001"); err == nil {
		t.Fatal("expected error for node id 0")
	}
	if err := client.AddNode(ctx, 2, ""); err == nil {
		t.Fatal("expected error for empty address")
	}
	err := client.AddNode(ctx, 2, "host:63001")
	if err == nil {
		t.Fatal("expected error when raft client not configured")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("error = %v", err)
	}
}

func TestRemoveNodeValidation(t *testing.T) {
	ctx := context.Background()

	var nilClient *Client
	if err := nilClient.RemoveNode(ctx, 2); err == nil {
		t.Fatal("expected error for nil client")
	}

	client := &Client{nodeID: 1}
	if err := client.RemoveNode(ctx, 0); err == nil {
		t.Fatal("expected error for node id 0")
	}
	err := client.RemoveNode(ctx, 1)
	if err == nil {
		t.Fatal("expected error removing local node")
	}
	if !strings.Contains(err.Error(), "cannot remove local") {
		t.Fatalf("error = %v", err)
	}
	if err := client.RemoveNode(ctx, 2); err == nil {
		t.Fatal("expected error when raft client not configured")
	}
}
