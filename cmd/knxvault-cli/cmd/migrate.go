package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kubenexis/knxvault/internal/backup"
	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/crypto/masterkey"
	"github.com/kubenexis/knxvault/internal/migrate"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Storage migration commands",
}

var migratePostgresCmd = &cobra.Command{
	Use:   "postgres",
	Short: "Migrate PostgreSQL data into a running Raft-backed KNXVault via restore API",
	RunE: func(cmd *cobra.Command, _ []string) error {
		archivePath, _ := cmd.Flags().GetString("archive")
		if archivePath != "" {
			raw, err := os.ReadFile(archivePath)
			if err != nil {
				return err
			}
			return apiClient().BackupRestore(cmd.Context(), raw)
		}

		dsn, _ := cmd.Flags().GetString("from-dsn")
		if dsn == "" {
			return fmt.Errorf("either --from-dsn or --archive is required")
		}
		includeAudit, _ := cmd.Flags().GetBool("include-audit")

		snapshot, err := migrate.ExportFromPostgres(cmd.Context(), dsn, includeAudit)
		if err != nil {
			return err
		}
		if err := backup.ValidateSnapshot(snapshot); err != nil {
			return err
		}

		key, err := masterkey.Load()
		if err != nil {
			return fmt.Errorf("KNXVAULT_MASTER_KEY required to seal migration archive: %w", err)
		}
		cryptoSvc, err := crypto.NewService(key)
		if err != nil {
			return err
		}
		sealed, err := backup.Seal(cryptoSvc, snapshot)
		if err != nil {
			return err
		}
		return apiClient().BackupRestore(cmd.Context(), sealed)
	},
}

func init() {
	migratePostgresCmd.Flags().String("from-dsn", "", "PostgreSQL DSN to export")
	migratePostgresCmd.Flags().Bool("include-audit", false, "Include audit log entries")
	migratePostgresCmd.Flags().String("archive", "", "Restore an existing encrypted archive instead of exporting Postgres")
	migrateCmd.AddCommand(migratePostgresCmd)
}
