package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/kubenexis/knxvault/pkg/client"
)

var (
	addr  string
	token string
)

// Execute runs the CLI root command.
func Execute() error {
	return rootCmd.Execute()
}

var rootCmd = &cobra.Command{
	Use:   "knxvault-cli",
	Short: "KNXVault CLI — secure secrets and PKI management",
}

func init() {
	rootCmd.PersistentFlags().StringVar(&addr, "addr", envOr("KNXVAULT_ADDR", "http://localhost:8200"), "KNXVault API address")
	rootCmd.PersistentFlags().StringVar(&token, "token", os.Getenv("KNXVAULT_TOKEN"), "Client token")

	rootCmd.AddCommand(healthCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(authCmd)
	rootCmd.AddCommand(kvCmd)
	rootCmd.AddCommand(pkiCmd)
	rootCmd.AddCommand(backupCmd)
}

func apiClient() *client.Client {
	return client.New(addr, token)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
