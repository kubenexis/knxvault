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

Load base settings from a YAML file with -c/--config. Environment variables
override file values (useful for secrets and per-pod overrides in Kubernetes).

  knxvault serve -c /etc/knxvault/config.yaml`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVarP(&configFile, "config", "c", "", "YAML configuration file (base settings)")
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
	if configFile != "" {
		return config.LoadFile(configFile)
	}
	return config.Load()
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
