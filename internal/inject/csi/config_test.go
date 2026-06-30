package csi_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/inject/csi"
)

func TestParseMountConfig(t *testing.T) {
	attrs := `{
		"vaultAddr": "http://knxvault:8200",
		"role": "app-sa",
		"objects": "- path: app/db\n  fileName: db.env\n",
		"csi.storage.k8s.io/pod.name": "demo",
		"csi.storage.k8s.io/pod.namespace": "default"
	}`
	secrets := `{"serviceAccountToken":"jwt-token"}`
	cfg, err := csi.ParseMountConfig(attrs, secrets)
	if err != nil {
		t.Fatalf("ParseMountConfig() = %v", err)
	}
	if cfg.Role != "app-sa" || cfg.SAToken != "jwt-token" || len(cfg.Objects) != 1 {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}
	if cfg.Objects[0].FileName != "db.env" {
		t.Fatalf("fileName = %q", cfg.Objects[0].FileName)
	}
}
