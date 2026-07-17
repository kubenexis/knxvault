// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kubenexis/knxvault/pkg/client"
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup and restore commands",
}

var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an encrypted backup archive",
	RunE: func(cmd *cobra.Command, _ []string) error {
		output, _ := cmd.Flags().GetString("output")
		includeAudit, _ := cmd.Flags().GetBool("include-audit")

		resp, err := apiClient().BackupCreate(cmd.Context(), client.BackupCreateRequest{
			IncludeAudit: includeAudit,
		})
		if err != nil {
			return err
		}
		raw, err := base64.StdEncoding.DecodeString(resp.Data)
		if err != nil {
			return fmt.Errorf("decode backup: %w", err)
		}
		if output == "" || output == "-" {
			_, err = os.Stdout.Write(raw)
			return err
		}
		return os.WriteFile(output, raw, 0o600)
	},
}

var backupRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore from an encrypted backup archive",
	RunE: func(cmd *cobra.Command, _ []string) error {
		input, _ := cmd.Flags().GetString("file")
		if input == "" {
			return fmt.Errorf("--file is required")
		}
		raw, err := os.ReadFile(input)
		if err != nil {
			return err
		}
		return apiClient().BackupRestore(cmd.Context(), raw)
	},
}

func init() {
	backupCreateCmd.Flags().StringP("output", "o", "-", "Output file (- for stdout)")
	backupCreateCmd.Flags().Bool("include-audit", false, "Include audit log entries")
	backupRestoreCmd.Flags().StringP("file", "f", "", "Backup archive file")
	backupCmd.AddCommand(backupCreateCmd, backupRestoreCmd)
}
