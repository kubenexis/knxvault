package database

import "testing"

func TestParseConnectionURLPostgres(t *testing.T) {
	dsn, driver, err := parseConnectionURL("postgresql://admin:pass@db.internal:5432/app?sslmode=require")
	if err != nil {
		t.Fatalf("parseConnectionURL() = %v", err)
	}
	if driver != "pgx" {
		t.Fatalf("driver = %q, want pgx", driver)
	}
	if dsn != "postgres://admin:pass@db.internal:5432/app?sslmode=require" {
		t.Fatalf("dsn = %q", dsn)
	}
}

func TestParseConnectionURLCNPGServiceHost(t *testing.T) {
	raw := "postgres://vault_admin:secret@my-pg-rw.default.svc.cluster.local:5432/app?sslmode=require"
	_, driver, err := parseConnectionURL(raw)
	if err != nil {
		t.Fatalf("parseConnectionURL() = %v", err)
	}
	if driver != "pgx" {
		t.Fatalf("driver = %q, want pgx", driver)
	}
}
