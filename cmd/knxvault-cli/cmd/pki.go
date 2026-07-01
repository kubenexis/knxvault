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

var pkiRootCmd = &cobra.Command{
	Use:   "root",
	Short: "Create a self-signed root CA",
	RunE: func(cmd *cobra.Command, _ []string) error {
		name, _ := cmd.Flags().GetString("name")
		cn, _ := cmd.Flags().GetString("common-name")
		ttl, _ := cmd.Flags().GetString("ttl")
		keyBits, _ := cmd.Flags().GetInt("key-bits")

		resp, err := apiClient().PKICreateRoot(cmd.Context(), client.CreateRootCARequest{
			Name:       name,
			CommonName: cn,
			TTL:        ttl,
			KeyBits:    keyBits,
		})
		if err != nil {
			return err
		}
		return encodeJSON(os.Stdout, resp)
	},
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

var pkiRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a certificate serial",
	RunE: func(cmd *cobra.Command, _ []string) error {
		caID, _ := cmd.Flags().GetString("ca-id")
		serial, _ := cmd.Flags().GetString("serial")
		reason, _ := cmd.Flags().GetString("reason")
		return apiClient().PKIRevoke(cmd.Context(), client.RevokeCertRequest{
			CAID:   caID,
			Serial: serial,
			Reason: reason,
		})
	},
}

var pkiRenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew a leaf certificate",
	RunE: func(cmd *cobra.Command, _ []string) error {
		caID, _ := cmd.Flags().GetString("ca-id")
		serial, _ := cmd.Flags().GetString("serial")
		ttl, _ := cmd.Flags().GetString("ttl")
		resp, err := apiClient().PKIRenew(cmd.Context(), client.RenewCertRequest{
			CAID:   caID,
			Serial: serial,
			TTL:    ttl,
		})
		if err != nil {
			return err
		}
		return encodeJSON(os.Stdout, resp)
	},
}

func init() {
	pkiRootCmd.Flags().String("name", "", "CA name (used as issuance role)")
	pkiRootCmd.Flags().String("common-name", "", "Certificate common name")
	pkiRootCmd.Flags().String("ttl", "8760h", "CA TTL")
	pkiRootCmd.Flags().Int("key-bits", 2048, "RSA key size")
	_ = pkiRootCmd.MarkFlagRequired("name")
	_ = pkiRootCmd.MarkFlagRequired("common-name")
	pkiIssueCmd.Flags().String("role", "", "Issuing CA role name")
	pkiIssueCmd.Flags().String("common-name", "", "Certificate common name")
	pkiIssueCmd.Flags().String("ttl", "24h", "Certificate TTL")
	pkiIssueCmd.Flags().Bool("auto-renew", false, "Enable auto-renewal tracking")
	pkiIssueCmd.Flags().StringSlice("dns", nil, "DNS SAN entries")
	_ = pkiIssueCmd.MarkFlagRequired("role")
	_ = pkiIssueCmd.MarkFlagRequired("common-name")
	pkiRevokeCmd.Flags().String("ca-id", "", "CA identifier")
	pkiRevokeCmd.Flags().String("serial", "", "Certificate serial to revoke")
	pkiRevokeCmd.Flags().String("reason", "", "Revocation reason")
	_ = pkiRevokeCmd.MarkFlagRequired("ca-id")
	_ = pkiRevokeCmd.MarkFlagRequired("serial")
	pkiRenewCmd.Flags().String("ca-id", "", "CA identifier")
	pkiRenewCmd.Flags().String("serial", "", "Certificate serial to renew")
	pkiRenewCmd.Flags().String("ttl", "", "Renewal TTL (optional)")
	_ = pkiRenewCmd.MarkFlagRequired("ca-id")
	_ = pkiRenewCmd.MarkFlagRequired("serial")
	pkiCmd.AddCommand(pkiRootCmd, pkiIssueCmd, pkiRevokeCmd, pkiRenewCmd)
}
