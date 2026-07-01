package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log operations",
}

var auditExportLimit int

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit log entries",
	RunE: func(cmd *cobra.Command, _ []string) error {
		result, err := apiClient().ExportAudit(cmd.Context(), auditExportLimit)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	auditExportCmd.Flags().IntVar(&auditExportLimit, "limit", 100, "Maximum entries to export")
	auditCmd.AddCommand(auditExportCmd)
	rootCmd.AddCommand(auditCmd)
}