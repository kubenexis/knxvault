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

type staticRoleResolver struct {
	role *domainauth.Role
}

func (s staticRoleResolver) PoliciesForRole(context.Context, string) []string {
	return s.role.Policies
}

func (s staticRoleResolver) GetRole(context.Context, string) (*domainauth.Role, error) {
	copy := *s.role
	return &copy, nil
}

func TestLoginKubernetesFailsClosedProduction(t *testing.T) {
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	svc.SetK8sLoginOptions(auth.K8sLoginOptions{RaftEnabled: true})
	_, _, err := svc.LoginKubernetes(context.Background(), "admin", "token")
	var kv *common.KNXVaultError
	if !errors.As(err, &kv) || kv.Code != common.ErrCodeUnauthorized {
		t.Fatalf("expected unauthorized, got %v", err)
	}
}

func TestLoginKubernetesInsecureDev(t *testing.T) {
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	svc.SetK8sLoginOptions(auth.K8sLoginOptions{InsecureDev: true})
	token, rec, err := svc.LoginKubernetes(context.Background(), "admin", "anything")
	if err != nil {
		t.Fatalf("LoginKubernetes() = %v", err)
	}
	if token == "" || rec == nil {
		t.Fatal("expected issued token")
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
	token, record, err := svc.CreateToken(context.Background(), "ci-bot", []string{"secrets-admin"}, 30*time.Minute, true)
	if err != nil {
		t.Fatalf("CreateToken() = %v", err)
	}
	if token == "" || !record.Renewable {
		t.Fatal("expected renewable token")
	}
	renewed, err := svc.RenewToken(context.Background(), token, time.Hour)
	if err != nil {
		t.Fatalf("RenewToken() = %v", err)
	}
	if renewed.ExpiresAt.Before(record.ExpiresAt) {
		t.Fatal("expected extended expiry")
	}
	if err := svc.RevokeToken(context.Background(), token); err != nil {
		t.Fatalf("RevokeToken() = %v", err)
	}
	if _, err := svc.LoginWithToken(context.Background(), token); err == nil {
		t.Fatal("expected revoked token to fail authentication")
	}
}

func TestLoginKubernetesHS256Dev(t *testing.T) {
	secret := []byte("dev-secret")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "system:serviceaccount:default:app"})
	signed, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	svc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), string(secret))
	svc.SetK8sLoginOptions(auth.K8sLoginOptions{})
	clientToken, rec, err := svc.LoginKubernetes(context.Background(), "admin", signed)
	if err != nil {
		t.Fatalf("LoginKubernetes() = %v", err)
	}
	if clientToken == "" || rec.Subject == "" {
		t.Fatal("expected token")
	}
}
