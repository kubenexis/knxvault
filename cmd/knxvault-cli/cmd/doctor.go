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

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose KNXVault deployment health and CLI configuration",
	Long: `Run standard checks against a KNXVault deployment:

  - CLI configuration (address, token, TLS)
  - API connectivity, liveness, and readiness
  - Seal, Raft, and HA leadership status
  - Metrics endpoint availability
  - Client token validity (when configured)

Exit code is 1 when any check fails; warnings do not fail the command.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		report := (&doctor.Runner{
			Client: apiClient(),
			Config: doctor.Config{
				Addr:       addr,
				Token:      token,
				ConfigFile: viper.ConfigFileUsed(),
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
	rootCmd.AddCommand(doctorCmd)
}
