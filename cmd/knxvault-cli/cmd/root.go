// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/kubenexis/knxvault/internal/version"
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
	Use:     "knxvault-cli",
	Short:   "KNXVault CLI — secure secrets and PKI management",
	Version: version.String(),
}

func init() {
	cobra.OnInitialize(initConfig, announceBuild)
	rootCmd.SetVersionTemplate("{{.Version}}\n")

	rootCmd.PersistentFlags().StringVar(&addr, "addr", "http://localhost:8200", "KNXVault API address")
	rootCmd.PersistentFlags().StringVar(&token, "token", "", "Client token")
	_ = viper.BindPFlag("addr", rootCmd.PersistentFlags().Lookup("addr"))
	_ = viper.BindPFlag("token", rootCmd.PersistentFlags().Lookup("token"))
	_ = viper.BindEnv("addr", "KNXVAULT_ADDR")
	_ = viper.BindEnv("token", "KNXVAULT_TOKEN")

	rootCmd.AddCommand(healthCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(authCmd)
	rootCmd.AddCommand(kvCmd)
	rootCmd.AddCommand(pkiCmd)
	rootCmd.AddCommand(backupCmd)
	rootCmd.AddCommand(completionCmd)
}

func announceBuild() {
	version.AnnounceStandard("knxvault-cli")
}

func initConfig() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(filepath.Join(home, ".knxvault"))
	_ = viper.ReadInConfig()

	if v := viper.GetString("addr"); v != "" {
		addr = v
	}
	if v := viper.GetString("token"); v != "" && token == "" {
		token = v
	}
	if token == "" {
		token = os.Getenv("KNXVAULT_TOKEN")
	}
}

func apiClient() *client.Client {
	return client.New(addr, token)
}
