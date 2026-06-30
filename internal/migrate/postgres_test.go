package migrate_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/migrate"
)

func TestExportFromPostgresRequiresDSN(t *testing.T) {
	_, err := migrate.ExportFromPostgres(context.Background(), "", false)
	if err == nil {
		t.Fatal("expected error for empty dsn")
	}
}
