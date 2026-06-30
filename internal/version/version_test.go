package version_test

import (
	"bytes"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/kubenexis/knxvault/internal/version"
)

func TestGetAndString(t *testing.T) {
	info := version.Get()
	if info.Version != "0.4.5" {
		t.Fatalf("Version = %q, want 0.4.5", info.Version)
	}
	if !strings.Contains(version.String(), info.Version) {
		t.Fatalf("String() = %q, want version substring", version.String())
	}
	if !strings.Contains(version.String(), "commit=") {
		t.Fatal("String() should include commit")
	}
	if !strings.Contains(version.String(), "build=") {
		t.Fatal("String() should include build id")
	}
}

func TestHandleArgs(t *testing.T) {
	if version.HandleArgs([]string{"serve"}) {
		t.Fatal("unexpected version handling")
	}
}

func TestPrint(t *testing.T) {
	var buf bytes.Buffer
	version.Print(&buf)
	if !strings.Contains(buf.String(), "0.4.5") {
		t.Fatalf("Print() = %q", buf.String())
	}
}

func TestAnnounceZap(t *testing.T) {
	core, recorded := observer.New(zap.InfoLevel)
	log := zap.New(core)
	version.AnnounceZap(log, "knxvault-test")
	entries := recorded.All()
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["version"] != "0.4.5" {
		t.Fatalf("logged version = %v", fields["version"])
	}
	if _, ok := fields["commit"]; !ok {
		t.Fatal("expected commit field")
	}
	if _, ok := fields["build_id"]; !ok {
		t.Fatal("expected build_id field")
	}
}
