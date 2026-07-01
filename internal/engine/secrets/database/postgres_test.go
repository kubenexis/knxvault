package database_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/engine/secrets/database"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestSaveRoleCNPGAppliesDefaultStatements(t *testing.T) {
	cryptoSvc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	roles := memory.NewDatabaseRoleRepository()
	engine := database.NewEngine(roles, memory.NewLeaseRepository(), memory.NewSecretRepository(), cryptoSvc)
	ctx := context.Background()

	if err := engine.SaveRole(ctx, database.RoleConfig{
		Name:           "cnpg-readonly",
		TTLSeconds:     3600,
		UsernamePrefix: "v-",
		Config: map[string]any{
			"db_type":       "cnpg",
			"database_name": "app",
			"schema":        "public",
			"privilege":     "readonly",
		},
	}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}

	role, err := roles.Get(ctx, "cnpg-readonly")
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if len(role.CreationStatements) == 0 || len(role.RevocationStatements) == 0 {
		t.Fatal("expected default postgres statements for cnpg role")
	}
	joined := strings.Join(role.CreationStatements, "\n")
	if !strings.Contains(joined, "CREATE ROLE") || !strings.Contains(joined, "GRANT SELECT") {
		t.Fatalf("unexpected creation statements: %s", joined)
	}
}

func TestGenerateCredentialsCNPGStatements(t *testing.T) {
	cryptoSvc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	roles := memory.NewDatabaseRoleRepository()
	leases := memory.NewLeaseRepository()
	secretRepo := memory.NewSecretRepository()
	engine := database.NewEngine(roles, leases, secretRepo, cryptoSvc)
	ctx := context.Background()

	if err := engine.SaveRole(ctx, database.RoleConfig{
		Name:           "cnpg-app",
		TTLSeconds:     600,
		UsernamePrefix: "v-",
		Config: map[string]any{
			"db_type":       "postgresql",
			"database_name": "payments",
			"schema":        "app",
		},
	}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}

	result, err := engine.GenerateCredentials(ctx, database.CredsRequest{Role: "cnpg-app"})
	if err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	if len(result.Statements) == 0 {
		t.Fatal("expected rendered creation statements")
	}
	stmt := strings.Join(result.Statements, "\n")
	if !strings.Contains(stmt, `"payments"`) || !strings.Contains(stmt, `"app"`) {
		t.Fatalf("statements missing database/schema: %s", stmt)
	}
	if !strings.Contains(stmt, "VALID UNTIL") {
		t.Fatalf("statements missing expiration: %s", stmt)
	}
}

func TestBuildConnectionURLFromFields(t *testing.T) {
	url, err := database.BuildConnectionURL(map[string]any{
		"username": "vault_admin",
		"password": "s3cret",
		"host":     "my-cluster-rw.default.svc",
		"port":     "5432",
		"database": "app",
	}, map[string]any{
		"ssl_mode": "require",
	})
	if err != nil {
		t.Fatalf("BuildConnectionURL() = %v", err)
	}
	if !strings.HasPrefix(url, "postgres://") {
		t.Fatalf("url = %q", url)
	}
	if !strings.Contains(url, "sslmode=require") {
		t.Fatalf("url = %q, want sslmode=require", url)
	}
}

func TestBuildConnectionURLPrefersExplicitURL(t *testing.T) {
	raw := "postgres://admin:pass@db:5432/app?sslmode=disable"
	url, err := database.BuildConnectionURL(map[string]any{
		"connection_url": raw,
		"host":           "ignored",
	}, nil)
	if err != nil {
		t.Fatalf("BuildConnectionURL() = %v", err)
	}
	if url != raw {
		t.Fatalf("url = %q, want %q", url, raw)
	}
}

func TestManagedPostgresUsesConnectionURLBuilder(t *testing.T) {
	cryptoSvc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	roles := memory.NewDatabaseRoleRepository()
	leases := memory.NewLeaseRepository()
	secretRepo := memory.NewSecretRepository()
	runner := &captureSQLRunner{}
	engine := database.NewEngine(roles, leases, secretRepo, cryptoSvc)
	engine.SetSQLRunner(runner)
	ctx := context.Background()

	adminPayload, _ := json.Marshal(map[string]any{
		"username": "cnpg_admin",
		"password": "admin-pass",
		"host":     "pg-rw.default.svc",
		"port":     "5432",
		"database": "app",
	})
	adminEnc, adminDEK, err := cryptoSvc.Seal(adminPayload)
	if err != nil {
		t.Fatalf("Seal() = %v", err)
	}
	if err := secretRepo.SaveVersion(ctx, &secrets.SecretVersion{
		ID: uuid.New(), Path: "database/admin/cnpg", Version: 1,
		DataEnc: adminEnc, DEKEnc: adminDEK,
	}); err != nil {
		t.Fatalf("SaveVersion() = %v", err)
	}

	if err := engine.SaveRole(ctx, database.RoleConfig{
		Name:                 "cnpg-managed",
		TTLSeconds:           300,
		ExecutionMode:        secrets.ExecutionModeManaged,
		AdminCredentialsPath: "database/admin/cnpg",
		Config: map[string]any{
			"db_type":       "cnpg",
			"database_name": "app",
			"ssl_mode":      "require",
		},
	}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}

	if _, err := engine.GenerateCredentials(ctx, database.CredsRequest{Role: "cnpg-managed"}); err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	if !strings.HasPrefix(runner.connURL, "postgres://") {
		t.Fatalf("connURL = %q", runner.connURL)
	}
	if len(runner.statements) == 0 {
		t.Fatal("expected creation statements executed")
	}
}

func TestRenderStatementsExpirationFormat(t *testing.T) {
	cryptoSvc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	engine := database.NewEngine(memory.NewDatabaseRoleRepository(), memory.NewLeaseRepository(), memory.NewSecretRepository(), cryptoSvc)
	ctx := context.Background()
	if err := engine.SaveRole(ctx, database.RoleConfig{
		Name:           "pg-exp",
		TTLSeconds:     120,
		UsernamePrefix: "v-",
		Config: map[string]any{
			"db_type":       "cnpg",
			"database_name": "app",
		},
	}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}
	result, err := engine.GenerateCredentials(ctx, database.CredsRequest{Role: "pg-exp", TTLSecond: 120})
	if err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	exp := result.ExpiresAt.UTC().Format("2006-01-02 15:04:05-07")
	found := false
	for _, stmt := range result.Statements {
		if strings.Contains(stmt, exp) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expiration %q not found in %v", exp, result.Statements)
	}
	if result.ExpiresAt.Before(time.Now().UTC()) {
		t.Fatal("expires_at should be in the future")
	}
}

type captureSQLRunner struct {
	connURL    string
	statements []string
}

func (c *captureSQLRunner) ExecStatements(_ context.Context, connectionURL string, statements []string) error {
	c.connURL = connectionURL
	c.statements = append(c.statements, statements...)
	return nil
}