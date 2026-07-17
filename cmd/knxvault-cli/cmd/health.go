// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check liveness",
	RunE: func(cmd *cobra.Command, _ []string) error {
		resp, err := apiClient().Health(cmd.Context())
		if err != nil {
			return err
		}
		return encodeJSON(os.Stdout, resp)
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check readiness and HA status",
	RunE: func(cmd *cobra.Command, _ []string) error {
		resp, err := apiClient().Ready(cmd.Context())
		if err != nil {
			return err
		}
		return encodeJSON(os.Stdout, resp)
	},
}

func encodeJSON(w interface{ Write([]byte) (int, error) }, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", raw)
	return err
}
