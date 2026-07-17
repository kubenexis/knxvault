// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/kubenexis/knxvault/pkg/doctor"
)

var doctorJSON bool
var doctorProfile string
var doctorMetricsAddr string
var doctorOIDC string
var doctorLDAP string
var doctorAuditForward string
var doctorACME string

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose KNXVault deployment health and CLI configuration",
	Long: `Run standard checks against a KNXVault deployment:

  - CLI configuration (address, token, TLS)
  - API connectivity, liveness, and readiness
  - Seal, Raft, and HA leadership status
  - Metrics endpoint availability
  - Client token validity (when configured)
  - Production profile gate (--profile production): TLS scheme, token, metrics plane notes
  - Feature gate posture (M-DTP-2): OIDC/LDAP/audit-forward/ACME expected values

Exit code is 1 when any check fails; warnings do not fail the command
(except production profile: fails still set exit 1).`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		// Prefer explicit flags; fall back to process env (same names as server ConfigMap).
		oidc := firstNonEmpty(doctorOIDC, os.Getenv("KNXVAULT_AUTH_OIDC_ENABLED"))
		ldap := firstNonEmpty(doctorLDAP, os.Getenv("KNXVAULT_AUTH_LDAP_ENABLED"))
		auditFwd := firstNonEmpty(doctorAuditForward, os.Getenv("KNXVAULT_AUDIT_FORWARD_ENABLED"))
		acme := firstNonEmpty(doctorACME, os.Getenv("KNXVAULT_ACME_RELATED_ENABLED"))
		report := (&doctor.Runner{
			Client: apiClient(),
			Config: doctor.Config{
				Addr:                addr,
				Token:               token,
				ConfigFile:          viper.ConfigFileUsed(),
				Profile:             doctorProfile,
				MetricsAddr:         doctorMetricsAddr,
				AuthOIDCEnabled:     oidc,
				AuthLDAPEnabled:     ldap,
				AuditForwardEnabled: auditFwd,
				ACMERelatedEnabled:  acme,
			},
		}).Run(cmd.Context())

		if doctorJSON {
			return encodeJSON(os.Stdout, report)
		}
		printDoctorReport(os.Stdout, report)
		if !report.Healthy {
			return fmt.Errorf("%d check(s) failed", report.Fail)
		}
		return nil
	},
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func printDoctorReport(w io.Writer, report *doctor.Report) {
	_, _ = fmt.Fprintf(w, "KNXVault Doctor — %s\n\n", report.Addr)
	for _, check := range report.Checks {
		_, _ = fmt.Fprintf(w, "[%s] %s\n", statusLabel(check.Status), check.ID)
		_, _ = fmt.Fprintf(w, "      %s\n", check.Message)
		if check.Detail != "" {
			_, _ = fmt.Fprintf(w, "      %s\n", check.Detail)
		}
	}
	_, _ = fmt.Fprintf(w, "\nSummary: %d passed, %d warning(s), %d failed, %d skipped\n",
		report.OK, report.Warn, report.Fail, report.Skip)
}

func statusLabel(status doctor.Status) string {
	switch status {
	case doctor.StatusOK:
		return " OK "
	case doctor.StatusWarn:
		return "WARN"
	case doctor.StatusFail:
		return "FAIL"
	case doctor.StatusSkip:
		return "SKIP"
	default:
		return strings.ToUpper(string(status))
	}
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorJSON, "json", false, "Emit report as JSON")
	doctorCmd.Flags().StringVar(&doctorProfile, "profile", "lab", "Doctor profile: lab|production (production enables fail-closed Day-0 checks)")
	doctorCmd.Flags().StringVar(&doctorMetricsAddr, "metrics-addr", "", "Dedicated metrics scrape address (production network split)")
	doctorCmd.Flags().StringVar(&doctorOIDC, "feature-oidc", "", "Expected KNXVAULT_AUTH_OIDC_ENABLED (true|false); default from env")
	doctorCmd.Flags().StringVar(&doctorLDAP, "feature-ldap", "", "Expected KNXVAULT_AUTH_LDAP_ENABLED (true|false); default from env")
	doctorCmd.Flags().StringVar(&doctorAuditForward, "feature-audit-forward", "", "Expected KNXVAULT_AUDIT_FORWARD_ENABLED; default from env")
	doctorCmd.Flags().StringVar(&doctorACME, "feature-acme", "", "Expected KNXVAULT_ACME_RELATED_ENABLED; default from env")
	rootCmd.AddCommand(doctorCmd)
}
