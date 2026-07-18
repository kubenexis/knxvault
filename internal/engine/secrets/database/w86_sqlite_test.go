// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package database_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/engine/secrets/database"
)

func TestW86_FileAdminURLsRejectedWhenDisabled(t *testing.T) {
	prev := database.AllowFileAdminURLs
	database.AllowFileAdminURLs = false
	t.Cleanup(func() { database.AllowFileAdminURLs = prev })

	runner := database.DefaultSQLRunner{}
	err := runner.ExecStatements(context.Background(), "sqlite:/tmp/x.db", []string{"SELECT 1"})
	if err == nil {
		t.Fatal("expected sqlite admin URL rejected when AllowFileAdminURLs=false")
	}
}
