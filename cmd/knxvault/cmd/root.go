// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

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
  knxvault serve

Configuration is read from /etc/knxvault.conf when present, or from -c/--config.
Environment variables override values from the configuration file.
Use -version to print build metadata.`,
	Version: version.String(),
}

func init() {
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Configuration file (default: /etc/knxvault.conf when present)")
	rootCmd.AddCommand(serveCmd)
}
