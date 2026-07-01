package cmd

import (
	"context"
	"encoding/json"
	"fmt"

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

func init() {
	auditExportCmd.Flags().Int("limit", 100, "Maximum entries to export")
	auditCmd.AddCommand(auditExportCmd)
	rootCmd.AddCommand(auditCmd)
}
