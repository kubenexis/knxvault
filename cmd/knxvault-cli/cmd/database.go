// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kubenexis/knxvault/pkg/client"
)

var databaseCmd = &cobra.Command{
	Use:   "database",
	Short: "Dynamic database credentials administration",
}

var databaseRolesPutCmd = &cobra.Command{
	Use:   "roles put <name> <json-file>",
	Short: "Create or update a database role",
	Args:  cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		raw, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		var req client.DatabaseRoleRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return err
		}
		return apiClient().PutDatabaseRole(context.Background(), args[0], req)
	},
}

var databaseRolesGetCmd = &cobra.Command{
	Use:   "roles get <name>",
	Short: "Get a database role",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		item, err := apiClient().GetDatabaseRole(context.Background(), args[0])
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(item, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var databaseCredsCmd = &cobra.Command{
	Use:   "creds <role>",
	Short: "Generate database credentials",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ttl, _ := cmd.Flags().GetInt("ttl")
		result, err := apiClient().GenerateDatabaseCreds(context.Background(), args[0], ttl)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	databaseCredsCmd.Flags().Int("ttl", 0, "Lease TTL in seconds")
	databaseCmd.AddCommand(databaseRolesPutCmd)
	databaseCmd.AddCommand(databaseRolesGetCmd)
	databaseCmd.AddCommand(databaseCredsCmd)
	rootCmd.AddCommand(databaseCmd)
}
