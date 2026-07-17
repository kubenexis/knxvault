// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authentication commands",
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Validate a client token",
	RunE: func(cmd *cobra.Command, _ []string) error {
		loginToken, _ := cmd.Flags().GetString("token")
		if loginToken == "" {
			loginToken = token
		}
		if loginToken == "" {
			return fmt.Errorf("token is required (--token or KNXVAULT_TOKEN)")
		}
		resp, err := apiClient().LoginToken(cmd.Context(), loginToken)
		if err != nil {
			return err
		}
		return encodeJSON(os.Stdout, resp)
	},
}

func init() {
	authLoginCmd.Flags().String("token", "", "Token to validate")
	authCmd.AddCommand(authLoginCmd)
}
