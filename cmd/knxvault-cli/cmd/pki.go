package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/kubenexis/knxvault/pkg/client"
)

var pkiCmd = &cobra.Command{
	Use:   "pki",
	Short: "PKI commands",
}

var pkiIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a leaf certificate",
	RunE: func(cmd *cobra.Command, _ []string) error {
		role, _ := cmd.Flags().GetString("role")
		cn, _ := cmd.Flags().GetString("common-name")
		ttl, _ := cmd.Flags().GetString("ttl")
		autoRenew, _ := cmd.Flags().GetBool("auto-renew")
		dns, _ := cmd.Flags().GetStringSlice("dns")

		resp, err := apiClient().PKIIssue(cmd.Context(), client.IssueCertRequest{
			Role:       role,
			CommonName: cn,
			DNSNames:   dns,
			TTL:        ttl,
			AutoRenew:  autoRenew,
		})
		if err != nil {
			return err
		}
		return encodeJSON(os.Stdout, resp)
	},
}

func init() {
	pkiIssueCmd.Flags().String("role", "", "Issuing CA role name")
	pkiIssueCmd.Flags().String("common-name", "", "Certificate common name")
	pkiIssueCmd.Flags().String("ttl", "24h", "Certificate TTL")
	pkiIssueCmd.Flags().Bool("auto-renew", false, "Enable auto-renewal tracking")
	pkiIssueCmd.Flags().StringSlice("dns", nil, "DNS SAN entries")
	_ = pkiIssueCmd.MarkFlagRequired("role")
	_ = pkiIssueCmd.MarkFlagRequired("common-name")
	pkiCmd.AddCommand(pkiIssueCmd)
}
