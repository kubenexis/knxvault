package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kubenexis/knxvault/pkg/client"
)

var policiesCmd = &cobra.Command{
	Use:   "policies",
	Short: "RBAC policy administration",
}

var policiesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List RBAC policies",
	RunE: func(cmd *cobra.Command, _ []string) error {
		items, err := apiClient().ListPolicies(cmd.Context())
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
	Short: "Get an RBAC policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		policy, err := apiClient().GetPolicy(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(policy, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var (
	policyEffect     string
	policyResources  []string
	policyActions    []string
)

var policiesPutCmd = &cobra.Command{
	Use:   "put <name>",
	Short: "Create or update an RBAC policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if policyEffect == "" || len(policyResources) == 0 || len(policyActions) == 0 {
			return fmt.Errorf("--effect, --resource, and --action are required")
		}
		if err := apiClient().PutPolicy(cmd.Context(), args[0], client.PolicyRequest{
			Effect:    policyEffect,
			Resources: policyResources,
			Actions:   policyActions,
		}); err != nil {
			return err
		}
		fmt.Println("policy saved")
		return nil
	},
}

var policiesDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete an RBAC policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := apiClient().DeletePolicy(cmd.Context(), args[0]); err != nil {
			return err
		}
		fmt.Println("policy deleted")
		return nil
	},
}

var rolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "Auth role bindings",
}

var rolesGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get an auth role binding",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		role, err := apiClient().GetRole(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(role, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var rolePolicies []string

var rolesPutCmd = &cobra.Command{
	Use:   "put <name>",
	Short: "Create or update an auth role binding",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(rolePolicies) == 0 {
			return fmt.Errorf("at least one --policy is required")
		}
		if err := apiClient().PutRole(cmd.Context(), args[0], client.RoleRequest{
			Policies: rolePolicies,
		}); err != nil {
			return err
		}
		fmt.Println("role saved")
		return nil
	},
}

func init() {
	policiesPutCmd.Flags().StringVar(&policyEffect, "effect", "allow", "Policy effect (allow|deny)")
	policiesPutCmd.Flags().StringSliceVar(&policyResources, "resource", nil, "Resource pattern (repeatable)")
	policiesPutCmd.Flags().StringSliceVar(&policyActions, "action", nil, "Action (repeatable)")
	rolesPutCmd.Flags().StringSliceVar(&rolePolicies, "policy", nil, "Bound policy name (repeatable)")

	policiesCmd.AddCommand(policiesListCmd, policiesGetCmd, policiesPutCmd, policiesDeleteCmd)
	rolesCmd.AddCommand(rolesGetCmd, rolesPutCmd)
	sysCmd.AddCommand(policiesCmd, rolesCmd)
}