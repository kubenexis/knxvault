package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kubenexis/knxvault/pkg/client"
)

var policiesCmd = &cobra.Command{
	Use:   "policies",
	Short: "RBAC policy administration",
}

var policiesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List policies",
	RunE: func(_ *cobra.Command, _ []string) error {
		items, err := apiClient().ListPolicies(context.Background())
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(items, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var policiesGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get a policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		item, err := apiClient().GetPolicy(context.Background(), args[0])
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(item, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var policiesPutCmd = &cobra.Command{
	Use:   "put <name> <json-file>",
	Short: "Create or update a policy from JSON file",
	Args:  cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		raw, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		var req client.PolicyRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return err
		}
		return apiClient().PutPolicy(context.Background(), args[0], req)
	},
}

var policiesDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return apiClient().DeletePolicy(context.Background(), args[0])
	},
}

var rolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "RBAC role administration",
}

var rolesGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get a role",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		item, err := apiClient().GetRole(context.Background(), args[0])
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(item, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var rolesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List roles",
	RunE: func(_ *cobra.Command, _ []string) error {
		items, err := apiClient().ListRoles(context.Background())
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(items, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var rolesDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a role",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return apiClient().DeleteRole(context.Background(), args[0])
	},
}

var rolesPutCmd = &cobra.Command{
	Use:   "put <name> <json-file>",
	Short: "Create or update a role from JSON file",
	Args:  cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		raw, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		var req client.RoleRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return err
		}
		return apiClient().PutRole(context.Background(), args[0], req)
	},
}

func init() {
	policiesCmd.AddCommand(policiesListCmd)
	policiesCmd.AddCommand(policiesGetCmd)
	policiesCmd.AddCommand(policiesPutCmd)
	policiesCmd.AddCommand(policiesDeleteCmd)
	rolesCmd.AddCommand(rolesListCmd)
	rolesCmd.AddCommand(rolesGetCmd)
	rolesCmd.AddCommand(rolesPutCmd)
	rolesCmd.AddCommand(rolesDeleteCmd)
	sysCmd.AddCommand(policiesCmd)
	sysCmd.AddCommand(rolesCmd)
}
