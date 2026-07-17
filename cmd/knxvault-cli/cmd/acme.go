// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/kubenexis/knxvault/internal/acme"
	"github.com/kubenexis/knxvault/internal/acme/filestore"
)

var acmeCmd = &cobra.Command{
	Use:   "acme",
	Short: "Public ACME / Let's Encrypt (not private PKI — use 'pki' for that)",
	Long: `ACME certificate automation for public CAs (Let's Encrypt, staging, Pebble).

Private platform CAs use: knxvault-cli pki …
Standalone and lab hosts use file delivery; Kubernetes prefers knxvault-operator ACME issuers.

See docs/design/acme-letsencrypt-unified.md`,
}

var acmeConfig string
var acmeStaging bool

func init() {
	acmeCmd.PersistentFlags().StringVar(&acmeConfig, "config", "", "ACME profile YAML path")
	acmeCmd.PersistentFlags().BoolVar(&acmeStaging, "staging", false, "Force Let's Encrypt staging directory")

	acmeRegisterCmd := &cobra.Command{
		Use:   "register",
		Short: "Create or load ACME account key for a profile",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := loadACMEProfile()
			if err != nil {
				return err
			}
			acct := acme.AccountKeyFile{Path: p.AccountKey}
			key, err := acct.LoadOrCreate()
			if err != nil {
				return err
			}
			return encodeJSON(os.Stdout, map[string]any{
				"account_key_file":  p.AccountKey,
				"created_or_loaded": true,
				"key_type":          fmt.Sprintf("%T", key),
				"directory_url":     p.DirectoryURL,
			})
		},
	}

	acmeIssueCmd := &cobra.Command{
		Use:   "issue",
		Short: "Obtain a certificate via ACME and write delivery paths",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := loadACMEProfile()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
			defer cancel()
			res, err := acme.RunIssue(ctx, p)
			if err != nil {
				return err
			}
			return encodeJSON(os.Stdout, map[string]any{
				"common_name": p.Domains[0].Name,
				"not_after":   res.NotAfter,
				"serial":      res.Serial,
				"cert_path":   p.Delivery.CertPath,
				"key_path":    p.Delivery.KeyPath,
			})
		},
	}

	acmeRenewCmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew certificate if within renew_before window",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := loadACMEProfile()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
			defer cancel()
			renewed, res, err := acme.RunRenew(ctx, p)
			if err != nil {
				return err
			}
			out := map[string]any{"renewed": renewed}
			if res != nil {
				out["not_after"] = res.NotAfter
				out["serial"] = res.Serial
			}
			return encodeJSON(os.Stdout, out)
		},
	}

	acmeStatusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show ACME cert state from state file (no private key)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := loadACMEProfile()
			if err != nil {
				return err
			}
			statePath := p.StateFile
			if statePath == "" {
				statePath = p.Delivery.CertPath + ".acme-state.json"
			}
			rec, err := (filestore.CertStateFile{Path: statePath}).Load()
			if err != nil {
				return err
			}
			if rec == nil {
				return encodeJSON(os.Stdout, map[string]any{"present": false, "state_file": statePath})
			}
			return encodeJSON(os.Stdout, map[string]any{
				"present":       true,
				"common_name":   rec.CommonName,
				"not_after":     rec.NotAfter,
				"directory_url": rec.DirectoryURL,
				"cert_path":     rec.CertPath,
				"needs_renew":   rec.NeedsRenew(time.Now().UTC(), p.RenewBeforeDuration()),
			})
		},
	}

	acmeDoctorCmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check ACME profile configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := loadACMEProfile()
			if err != nil {
				// still print error as JSON list
				return encodeJSON(os.Stdout, map[string]any{"ok": false, "checks": []string{err.Error()}})
			}
			checks := acme.DoctorProfile(p)
			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
			defer cancel()
			cfg := p.ToConfig(nil)
			info := acme.NewClient(cfg, nil, nil).ProbeDirectory(ctx)
			checks = append(checks, fmt.Sprintf("directory probe: ready=%v %s", info.Ready, info.Message))
			ok := info.Ready
			for _, c := range checks {
				if len(c) > 9 && c[:9] == "validate:" {
					ok = false
				}
			}
			return encodeJSON(os.Stdout, map[string]any{"ok": ok, "checks": checks})
		},
	}

	acmeAgentCmd := &cobra.Command{
		Use:   "agent",
		Short: "Long-running renew loop (M-ACME-2 / W60-17)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			interval, _ := cmd.Flags().GetDuration("interval")
			if interval <= 0 {
				interval = time.Hour
			}
			p, err := loadACMEProfile()
			if err != nil {
				return err
			}
			cmd.Printf("acme agent: profile=%s interval=%s (Ctrl+C to stop)\n", p.Name, interval)
			for {
				ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
				renewed, _, err := acme.RunRenew(ctx, p)
				cancel()
				if err != nil {
					cmd.PrintErrf("acme agent renew error: %v\n", err)
				} else if renewed {
					cmd.Printf("acme agent: renewed certificate\n")
				}
				select {
				case <-cmd.Context().Done():
					return nil
				case <-time.After(interval):
				}
			}
		},
	}
	acmeAgentCmd.Flags().Duration("interval", time.Hour, "Renew check interval")

	acmeCmd.AddCommand(acmeRegisterCmd, acmeIssueCmd, acmeRenewCmd, acmeStatusCmd, acmeDoctorCmd, acmeAgentCmd)
	rootCmd.AddCommand(acmeCmd)
}

func loadACMEProfile() (*acme.Profile, error) {
	if acmeConfig == "" {
		return nil, fmt.Errorf("--config profile.yaml is required")
	}
	p, err := acme.LoadProfileYAML(acmeConfig)
	if err != nil {
		return nil, err
	}
	if acmeStaging {
		p.DirectoryURL = acme.StagingDirectory
	}
	return p, nil
}
