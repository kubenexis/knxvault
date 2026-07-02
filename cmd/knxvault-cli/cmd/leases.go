package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
)

var leasesCmd = &cobra.Command{
	Use:   "leases",
	Short: "Unified lease administration (W42-02)",
}

var leasesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List leases",
	RunE: func(cmd *cobra.Command, _ []string) error {
		engine, _ := cmd.Flags().GetString("engine")
		role, _ := cmd.Flags().GetString("role")
		q := url.Values{}
		if engine != "" {
			q.Set("engine", engine)
		}
		if role != "" {
			q.Set("role", role)
		}
		query := q.Encode()
		resp, err := apiClient().ListLeases(context.Background(), query)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	leasesListCmd.Flags().String("engine", "", "filter by engine")
	leasesListCmd.Flags().String("role", "", "filter by role")
	leasesCmd.AddCommand(leasesListCmd)
	sysCmd.AddCommand(leasesCmd)
}
