// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var policySimulateCmd = &cobra.Command{
	Use:   "simulate",
	Short: "Simulate policy evaluation (W41-04)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		policies, _ := cmd.Flags().GetString("policies")
		resource, _ := cmd.Flags().GetString("resource")
		capability, _ := cmd.Flags().GetString("capability")
		req := map[string]any{
			"policies":   strings.Split(policies, ","),
			"resource":   resource,
			"capability": capability,
		}
		resp, err := apiClient().SimulatePolicy(context.Background(), req)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	policySimulateCmd.Flags().String("policies", "", "comma-separated policy names")
	policySimulateCmd.Flags().String("resource", "", "resource path")
	policySimulateCmd.Flags().String("capability", "read", "capability to test")
	_ = policySimulateCmd.MarkFlagRequired("policies")
	_ = policySimulateCmd.MarkFlagRequired("resource")
	policiesCmd.AddCommand(policySimulateCmd)
}
