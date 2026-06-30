package auth_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/auth"
)

func TestRBACAuthorize(t *testing.T) {
	rbac := auth.NewRBAC()
	req := auth.RequestContext{}
	if !rbac.Authorize([]string{"secrets-reader"}, "secrets/kv/app", "read", req) {
		t.Fatal("expected secrets read to be allowed")
	}
	if rbac.Authorize([]string{"secrets-reader"}, "secrets/kv/app", "write", req) {
		t.Fatal("expected secrets write to be denied")
	}
	if !rbac.Authorize([]string{"admin"}, "pki/root", "write", req) {
		t.Fatal("expected admin to be allowed")
	}
}
