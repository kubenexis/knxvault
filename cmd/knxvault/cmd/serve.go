// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/app"
	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/version"
)

var configFile string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the KNXVault HTTP server",
	Long: `Start the KNXVault API server in the foreground.

Loads /etc/knxvault.conf by default when that file exists, or an alternate path
from -c/--config on the root command. Environment variables override file values.`,
	RunE: runServe,
}

func runServe(_ *cobra.Command, _ []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	log, err := newLogger(cfg.LogLevel)
	if err != nil {
		return err
	}
	defer func() { _ = log.Sync() }()
	version.AnnounceZap(log, "knxvault")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	application, err := app.New(ctx, cfg, log)
	if err != nil {
		log.Error("bootstrap", zap.Error(err))
		return err
	}

	if err := application.Run(ctx); err != nil {
		log.Error("fatal", zap.Error(err))
		return err
	}
	return nil
}

func loadConfig() (config.Config, error) {
	return config.LoadResolved(configFile)
}

func newLogger(level string) (*zap.Logger, error) {
	var cfg zap.Config
	switch level {
	case "debug":
		cfg = zap.NewDevelopmentConfig()
	default:
		cfg = zap.NewProductionConfig()
	}
	return cfg.Build()
}
