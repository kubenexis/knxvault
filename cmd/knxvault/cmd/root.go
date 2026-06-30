package cmd

import (
	"github.com/spf13/cobra"

	"github.com/kubenexis/knxvault/internal/version"
)

// Execute runs the knxvault root command.
func Execute() error {
	return rootCmd.Execute()
}

var rootCmd = &cobra.Command{
	Use:   "knxvault",
	Short: "KNXVault — secrets management and PKI",
	Long: `KNXVault is a lightweight secrets manager and certificate authority.

Start the HTTP server (daemon mode):
  knxvault serve -c /etc/knxvault/config.yaml

Environment variables override values from the YAML file.
Use -version to print build metadata.`,
	Version: version.String(),
}

func init() {
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	rootCmd.AddCommand(serveCmd)
}
