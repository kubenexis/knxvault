package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/infra/k8s"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestLoginKubernetesFailsClosedProduction(t *testing.T) {
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	svc.SetK8sLoginOptions(auth.K8sLoginOptions{RaftEnabled: true})
	_, _, err := svc.LoginKubernetes(context.Background(), "admin", "token")
	var kv *common.KNXVaultError
	if !errors.As(err, &kv) || kv.Code != common.ErrCodeUnauthorized {
		t.Fatalf("expected unauthorized, got %v", err)
	}
}

func TestLoginKubernetesInsecureDevRequiresJWT(t *testing.T) {
	roleRepo := memory.NewRoleRepository()
	_ = roleRepo.Save(context.Background(), &domainauth.Role{
		Name:                          "app-sa",
		Policies:                      []string{"secrets-reader"},
		BoundServiceAccountNames:      []string{"app"},
		BoundServiceAccountNamespaces: []string{"default"},
	})
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	svc.SetRoleResolver(auth.NewRepositoryRoleResolver(roleRepo))
	svc.SetK8sLoginOptions(auth.K8sLoginOptions{InsecureDev: true})
	_, _, err := svc.LoginKubernetes(context.Background(), "app-sa", "not-a-jwt")
	if err == nil {
		t.Fatal("expected jwt parse error")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "system:serviceaccount:default:app",
	})
	unsigned, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	clientToken, rec, err := svc.LoginKubernetes(context.Background(), "app-sa", unsigned)
	if err != nil {
		t.Fatalf("LoginKubernetes() = %v", err)
	}
	if clientToken == "" || rec == nil {
		t.Fatal("expected issued token")
	}
}

func TestLoginKubernetesRequiresStoredRole(t *testing.T) {
	roleRepo := memory.NewRoleRepository()
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	svc.SetRoleResolver(auth.NewRepositoryRoleResolver(roleRepo))
	svc.SetK8sLoginOptions(auth.K8sLoginOptions{InsecureDev: true})
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "system:serviceaccount:default:app",
	})
	unsigned, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	_, _, err = svc.LoginKubernetes(context.Background(), "admin", unsigned)
	var kv *common.KNXVaultError
	if !errors.As(err, &kv) || kv.Code != common.ErrCodeForbidden {
		t.Fatalf("expected forbidden, got %v", err)
	}
}

func TestLoginKubernetesTokenReview(t *testing.T) {
	reviewer := &k8s.FakeTokenReviewer{
		Result: &k8s.TokenReviewResult{
			Authenticated:      true,
			Username:           "system:serviceaccount:prod:my-app",
			Namespace:          "prod",
			ServiceAccountName: "my-app",
		},
	}
	roleRepo := memory.NewRoleRepository()
	_ = roleRepo.Save(context.Background(), &domainauth.Role{
		Name:                          "app-sa",
		Policies:                      []string{"app"},
		BoundServiceAccountNames:      []string{"my-app"},
		BoundServiceAccountNamespaces: []string{"prod"},
	})
	resolver := auth.NewRepositoryRoleResolver(roleRepo)
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	svc.SetRoleResolver(resolver)
	svc.SetK8sLoginOptions(auth.K8sLoginOptions{TokenReviewer: reviewer})
	token, _, err := svc.LoginKubernetes(context.Background(), "app-sa", "sa-jwt")
	if err != nil {
		t.Fatalf("LoginKubernetes() = %v", err)
	}
	if token == "" || reviewer.Last != "sa-jwt" {
		t.Fatalf("unexpected token result")
	}
}

func TestLoginKubernetesTokenReviewBindingDenied(t *testing.T) {
	reviewer := &k8s.FakeTokenReviewer{
		Result: &k8s.TokenReviewResult{
			Authenticated:      true,
			Username:           "system:serviceaccount:prod:other",
			Namespace:          "prod",
			ServiceAccountName: "other",
		},
	}
	roleRepo := memory.NewRoleRepository()
	_ = roleRepo.Save(context.Background(), &domainauth.Role{
		Name:                          "app-sa",
		Policies:                      []string{"app"},
		BoundServiceAccountNames:      []string{"my-app"},
		BoundServiceAccountNamespaces: []string{"prod"},
	})
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	svc.SetRoleResolver(auth.NewRepositoryRoleResolver(roleRepo))
	svc.SetK8sLoginOptions(auth.K8sLoginOptions{TokenReviewer: reviewer})
	_, _, err := svc.LoginKubernetes(context.Background(), "app-sa", "sa-jwt")
	var kv *common.KNXVaultError
	if !errors.As(err, &kv) || kv.Code != common.ErrCodeForbidden {
		t.Fatalf("expected forbidden, got %v", err)
	}
}

func TestCreateRenewRevokeToken(t *testing.T) {
	store := auth.NewTokenStore(time.Hour)
	svc := auth.NewService(store, auth.NewRBAC(), "")
	ctx := context.Background()
	token, record, err := svc.CreateToken(ctx, "ci-bot", []string{"secrets-admin"}, 30*time.Minute, true)
	if err != nil {
		t.Fatalf("CreateToken() = %v", err)
	}
	if token == "" || !record.Renewable {
		t.Fatal("expected renewable token")
	}
	renewed, err := svc.RenewToken(ctx, token, time.Hour)
	if err != nil {
		t.Fatalf("RenewToken() = %v", err)
	}
	if renewed.ExpiresAt.Before(record.ExpiresAt) {
		t.Fatal("expected extended expiry")
	}
	if err := svc.RevokeToken(ctx, token); err != nil {
		t.Fatalf("RevokeToken() = %v", err)
	}
	if _, err := svc.LoginWithToken(ctx, token); err == nil {
		t.Fatal("expected revoked token to fail authentication")
	}
}

func TestLoginKubernetesRejectsOIDCAuthMethod(t *testing.T) {
	roleRepo := memory.NewRoleRepository()
	_ = roleRepo.Save(context.Background(), &domainauth.Role{
		Name:                          "oidc-only",
		AuthMethod:                    domainauth.AuthMethodOIDC,
		Policies:                      []string{"secrets-reader"},
		BoundServiceAccountNames:      []string{"app"},
		BoundServiceAccountNamespaces: []string{"default"},
	})
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	svc.SetRoleResolver(auth.NewRepositoryRoleResolver(roleRepo))
	svc.SetK8sLoginOptions(auth.K8sLoginOptions{InsecureDev: true})
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "system:serviceaccount:default:app",
	})
	unsigned, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	_, _, err = svc.LoginKubernetes(context.Background(), "oidc-only", unsigned)
	var kv *common.KNXVaultError
	if !errors.As(err, &kv) || kv.Code != common.ErrCodeForbidden {
		t.Fatalf("expected forbidden, got %v", err)
	}
}

func TestLoginKubernetesUsesPolicyGroups(t *testing.T) {
	roleRepo := memory.NewRoleRepository()
	_ = roleRepo.Save(context.Background(), &domainauth.Role{
		Name:                          "app-sa",
		Policies:                      []string{"secrets-reader"},
		PolicyGroups:                  []string{"audit-reader"},
		BoundServiceAccountNames:      []string{"app"},
		BoundServiceAccountNamespaces: []string{"default"},
	})
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	svc.SetRoleResolver(auth.NewRepositoryRoleResolver(roleRepo))
	svc.SetK8sLoginOptions(auth.K8sLoginOptions{InsecureDev: true})
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "system:serviceaccount:default:app",
	})
	unsigned, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	_, rec, err := svc.LoginKubernetes(context.Background(), "app-sa", unsigned)
	if err != nil {
		t.Fatalf("LoginKubernetes() = %v", err)
	}
	if len(rec.Policies) != 2 {
		t.Fatalf("policies = %v, want policy_groups merged", rec.Policies)
	}
}

func TestLoginKubernetesHS256Dev(t *testing.T) {
	secret := []byte("dev-secret")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "system:serviceaccount:default:app",
	})
	signed, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	roleRepo := memory.NewRoleRepository()
	_ = roleRepo.Save(context.Background(), &domainauth.Role{
		Name:                          "app-sa",
		Policies:                      []string{"secrets-reader"},
		BoundServiceAccountNames:      []string{"app"},
		BoundServiceAccountNamespaces: []string{"default"},
	})
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), string(secret))
	svc.SetRoleResolver(auth.NewRepositoryRoleResolver(roleRepo))
	svc.SetK8sLoginOptions(auth.K8sLoginOptions{})
	clientToken, rec, err := svc.LoginKubernetes(context.Background(), "app-sa", signed)
	if err != nil {
		t.Fatalf("LoginKubernetes() = %v", err)
	}
	if clientToken == "" || rec.Subject != "system:serviceaccount:default:app" {
		t.Fatalf("unexpected token: %+v", rec)
	}
}

func TestTokenRenewRespectsMaxExpiresAt(t *testing.T) {
	ctx := context.Background()
	store := auth.NewTokenStore(24 * time.Hour)
	maxAt := time.Now().UTC().Add(2 * time.Hour)
	token, _, err := store.Create(ctx, "oidc-user", []string{"read"}, time.Hour, true, maxAt)
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	renewed, err := store.Renew(ctx, token, 24*time.Hour)
	if err != nil {
		t.Fatalf("Renew() = %v", err)
	}
	if renewed.ExpiresAt.After(maxAt.Add(time.Second)) {
		t.Fatalf("ExpiresAt = %v exceeds max %v", renewed.ExpiresAt, maxAt)
	}
}

func TestTokenStoreReplicated(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewTokenRepository()
	store := auth.NewTokenStore(time.Hour)
	store.SetRepository(repo)

	token, _, err := store.Create(ctx, "bot", []string{"admin"}, time.Hour, false, time.Time{})
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}

	remote := auth.NewTokenStore(time.Hour)
	remote.SetRepository(repo)
	if _, err := remote.Authenticate(ctx, token); err != nil {
		t.Fatalf("Authenticate() on remote store = %v", err)
	}
}

func TestLoginWithTokenRejectsExpired(t *testing.T) {
	store := auth.NewTokenStore(time.Millisecond)
	svc := auth.NewService(store, auth.NewRBAC(), "")
	ctx := context.Background()
	token, _, err := svc.CreateToken(ctx, "bot", []string{"read"}, time.Millisecond, false)
	if err != nil {
		t.Fatalf("CreateToken() = %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := svc.LoginWithToken(ctx, token); err == nil {
		t.Fatal("expected expired token to fail")
	}
}

func TestRenewTokenRejectsNonRenewable(t *testing.T) {
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	ctx := context.Background()
	token, _, err := svc.CreateToken(ctx, "bot", []string{"read"}, time.Hour, false)
	if err != nil {
		t.Fatalf("CreateToken() = %v", err)
	}
	if _, err := svc.RenewToken(ctx, token, time.Hour); err == nil {
		t.Fatal("expected non-renewable token to fail renewal")
	}
}

func TestCreateTokenStoresPolicies(t *testing.T) {
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	ctx := context.Background()
	token, record, err := svc.CreateToken(ctx, "deploy", []string{"secrets-admin", "pki-issue"}, 2*time.Hour, true)
	if err != nil {
		t.Fatalf("CreateToken() = %v", err)
	}
	if len(record.Policies) != 2 {
		t.Fatalf("policies = %v", record.Policies)
	}
	got, err := svc.LoginWithToken(ctx, token)
	if err != nil {
		t.Fatalf("LoginWithToken() = %v", err)
	}
	if got.Subject != "deploy" {
		t.Fatalf("subject = %q", got.Subject)
	}
}
