package tenant_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/tenant"
)

func TestScopePath(t *testing.T) {
	got := tenant.ScopePath("team-a", "app/db", true)
	if got != "team-a/app/db" {
		t.Fatalf("ScopePath = %q", got)
	}
	if !tenant.ValidateAccess("team-a", "team-a/app/db", true) {
		t.Fatal("expected tenant access")
	}
	if tenant.ValidateAccess("team-a", "team-b/app/db", true) {
		t.Fatal("expected cross-tenant deny")
	}
}
