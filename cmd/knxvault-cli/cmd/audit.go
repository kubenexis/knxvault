package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log administration",
}

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit log entries",
	RunE: func(cmd *cobra.Command, _ []string) error {
		limit, _ := cmd.Flags().GetInt("limit")
		result, err := apiClient().AuditExport(context.Background(), limit)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var auditPackCmd = &cobra.Command{
	Use:   "pack",
	Short: "Export compliance audit pack (ZIP)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		sinceRaw, _ := cmd.Flags().GetString("since")
		outPath, _ := cmd.Flags().GetString("output")
		path := "/sys/audit/pack"
		if sinceRaw != "" {
			if _, err := time.Parse(time.RFC3339, sinceRaw); err != nil {
				return fmt.Errorf("invalid --since (RFC3339): %w", err)
			}
			path += "?since=" + sinceRaw
		}
		data, err := apiClient().GetRaw(context.Background(), path, true)
		if err != nil {
			return err
		}
		if outPath == "" {
			outPath = "knxvault-audit-pack.zip"
		}
		return os.WriteFile(outPath, data, 0o600)
	},
}

func init() {
	auditExportCmd.Flags().Int("limit", 100, "Maximum entries to export")
	auditPackCmd.Flags().String("since", "", "Export entries since RFC3339 timestamp")
	auditPackCmd.Flags().StringP("output", "o", "", "Output ZIP path (default knxvault-audit-pack.zip)")
	auditCmd.AddCommand(auditExportCmd)
	auditCmd.AddCommand(auditPackCmd)
	rootCmd.AddCommand(auditCmd)
}
