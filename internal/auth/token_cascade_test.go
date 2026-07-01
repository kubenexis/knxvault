package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
)

func TestTokenCascadeRevoke(t *testing.T) {
	store := auth.NewTokenStore(time.Hour)
	svc := auth.NewService(store, auth.NewRBAC(), "")
	ctx := context.Background()

	parent, parentRec, err := store.Create(ctx, "parent", []string{"admin"}, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	child, childRec, err := store.CreateWithOptions(ctx, "child", []string{"read"}, time.Hour, true, auth.CreateOptions{
		ParentID: parentRec.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	grandchild, _, err := store.CreateWithOptions(ctx, "grandchild", []string{"read"}, time.Hour, true, auth.CreateOptions{
		ParentID: childRec.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = grandchild

	if err := svc.RevokeToken(ctx, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, child); err == nil {
		t.Fatal("expected child revoked")
	}
}
