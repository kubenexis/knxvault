// Copyright Kubenexis Systems Private Limited.
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

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Dynamic OpenSSH credentials administration",
}

var sshRolesPutCmd = &cobra.Command{
	Use:   "roles put <name> <json-file>",
	Short: "Create or update an SSH role",
	Args:  cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		raw, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		var req client.SSHRoleRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return err
		}
		return apiClient().PutSSHRole(context.Background(), args[0], req)
	},
}

var sshRolesGetCmd = &cobra.Command{
	Use:   "roles get <name>",
	Short: "Get an SSH role",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		item, err := apiClient().GetSSHRole(context.Background(), args[0])
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(item, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var sshCredsCmd = &cobra.Command{
	Use:   "creds <role>",
	Short: "Generate OpenSSH credentials",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ttl, _ := cmd.Flags().GetInt("ttl")
		username, _ := cmd.Flags().GetString("username")
		result, err := apiClient().GenerateSSHCreds(context.Background(), args[0], username, ttl)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	sshCredsCmd.Flags().Int("ttl", 0, "Lease TTL in seconds")
	sshCredsCmd.Flags().String("username", "", "Target SSH username")
	sshCmd.AddCommand(sshRolesPutCmd)
	sshCmd.AddCommand(sshRolesGetCmd)
	sshCmd.AddCommand(sshCredsCmd)
	rootCmd.AddCommand(sshCmd)
}
