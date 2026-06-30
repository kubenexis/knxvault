package audit_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/domain/audit"
)

func TestEntryValidate(t *testing.T) {
	e := &audit.Entry{Action: "secrets.write", Status: "success"}
	if err := e.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestEntryRequiresAction(t *testing.T) {
	e := &audit.Entry{Status: "success"}
	if err := e.Validate(); err == nil {
		t.Fatal("expected error")
	}
}
