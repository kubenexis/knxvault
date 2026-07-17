// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package csi_test

import (
	"encoding/json"
	"testing"

	"github.com/kubenexis/knxvault/internal/inject/csi"
)

func TestW78_FileNameTraversalRejected(t *testing.T) {
	attrs, _ := json.Marshal(map[string]string{
		"role":    "r",
		"objects": "- path: secret/data/x\n  fileName: ../../etc/passwd\n",
	})
	if _, err := csi.ParseMountConfig(string(attrs), ""); err == nil {
		t.Fatal("expected rejection")
	}
	attrs2, _ := json.Marshal(map[string]string{
		"role":    "r",
		"objects": "- path: secret/data/x\n  fileName: good.txt\n",
	})
	cfg, err := csi.ParseMountConfig(string(attrs2), "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Objects[0].FileName != "good.txt" {
		t.Fatalf("got %q", cfg.Objects[0].FileName)
	}
}
