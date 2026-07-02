package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/kubenexis/knxvault/pkg/client"
)

var sysCmd = &cobra.Command{
	Use:   "sys",
	Short: "System administration commands",
}

var sysRotateMasterKeyCmd = &cobra.Command{
	Use:   "rotate-master-key [base64-key]",
	Short: "Rotate the envelope master key",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		resp, err := apiClient().RotateMasterKey(args[0])
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var sysSealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Seal the vault (block mutating operations)",
	RunE: func(_ *cobra.Command, _ []string) error {
		resp, err := apiClient().Seal()
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var sysUnsealCmd = &cobra.Command{
	Use:   "unseal [base64-key]",
	Short: "Unseal the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		resp, err := apiClient().Unseal(args[0])
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var sysRotationRunCmd = &cobra.Command{
	Use:   "rotation-run",
	Short: "Trigger orchestrated KV, database, and PKI rotation",
	RunE: func(cmd *cobra.Command, _ []string) error {
		req := client.RotationRunRequest{}
		if v, _ := cmd.Flags().GetString("db-grace"); v != "" {
			req.DBGrace = v
		}
		if v, _ := cmd.Flags().GetString("pki-grace"); v != "" {
			req.PKIGrace = v
		}
		resp, err := apiClient().RunRotation(context.Background(), req)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var sysRaftAddNodeCmd = &cobra.Command{
	Use:   "raft-add-node <node-id> <address>",
	Short: "Add a Raft cluster member",
	Args:  cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		nodeID, err := strconv.ParseUint(args[0], 10, 64)
		if err != nil {
			return err
		}
		return apiClient().RaftAddNode(context.Background(), client.RaftAddNodeRequest{
			NodeID:  nodeID,
			Address: args[1],
		})
	},
}

var sysRaftRemoveNodeCmd = &cobra.Command{
	Use:   "raft-remove-node <node-id>",
	Short: "Remove a Raft cluster member",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		nodeID, err := strconv.ParseUint(args[0], 10, 64)
		if err != nil {
			return err
		}
		return apiClient().RaftRemoveNode(context.Background(), client.RaftRemoveNodeRequest{NodeID: nodeID})
	},
}

var sysIssueListenerTLSCmd = &cobra.Command{
	Use:   "issue-listener-tls",
	Short: "Issue TLS certificate material for the API listener",
	RunE: func(cmd *cobra.Command, _ []string) error {
		role, _ := cmd.Flags().GetString("role")
		cn, _ := cmd.Flags().GetString("common-name")
		certFile, _ := cmd.Flags().GetString("cert-file")
		keyFile, _ := cmd.Flags().GetString("key-file")
		ttl, _ := cmd.Flags().GetString("ttl")
		req := client.IssueListenerTLSRequest{
			Role:       role,
			CommonName: cn,
			CertFile:   certFile,
			KeyFile:    keyFile,
			TTL:        ttl,
		}
		if dns, _ := cmd.Flags().GetStringSlice("dns"); len(dns) > 0 {
			req.DNSNames = dns
		}
		resp, err := apiClient().IssueListenerTLS(context.Background(), req)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	sysRotationRunCmd.Flags().String("db-grace", "", "Database lease renewal grace window (e.g. 24h)")
	sysRotationRunCmd.Flags().String("pki-grace", "", "PKI renewal grace window (e.g. 72h)")
	sysIssueListenerTLSCmd.Flags().String("role", "listener", "PKI role name")
	sysIssueListenerTLSCmd.Flags().String("common-name", "knxvault.local", "Certificate common name")
	sysIssueListenerTLSCmd.Flags().StringSlice("dns", nil, "DNS SAN entries")
	sysIssueListenerTLSCmd.Flags().String("cert-file", "", "Optional path to write certificate PEM")
	sysIssueListenerTLSCmd.Flags().String("key-file", "", "Optional path to write private key PEM")
	sysIssueListenerTLSCmd.Flags().String("ttl", "8760h", "Certificate TTL")
	sysCmd.AddCommand(sysRotateMasterKeyCmd)
	sysCmd.AddCommand(sysSealCmd)
	sysCmd.AddCommand(sysUnsealCmd)
	sysCmd.AddCommand(sysRotationRunCmd)
	sysCmd.AddCommand(sysRaftAddNodeCmd)
	sysCmd.AddCommand(sysRaftRemoveNodeCmd)
	sysCmd.AddCommand(sysIssueListenerTLSCmd)
	sysAuditCmd := &cobra.Command{Use: "audit", Short: "Audit administration"}
	sysAuditCmd.AddCommand(auditPackCmd)
	sysCmd.AddCommand(sysAuditCmd)
	rootCmd.AddCommand(sysCmd)
}
