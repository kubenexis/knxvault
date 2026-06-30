// Package app bootstraps and runs the KNXVault HTTP server.
package app

import (
	"context"
	"fmt"
	"net/http"

	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/api"
	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/infra/tracing"
)

// App owns the HTTP server lifecycle.
type App struct {
	cfg             config.Config
	log             *zap.Logger
	deps            *Dependencies
	server          *http.Server
	tracingShutdown func(context.Context) error
}

// New constructs an App from configuration.
func New(ctx context.Context, cfg config.Config, log *zap.Logger) (*App, error) {
	traceShutdown, err := tracing.Init(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("tracing: %w", err)
	}

	deps, err := NewDependencies(ctx, cfg, log)
	if err != nil {
		return nil, err
	}

	router := api.NewRouter(log, cfg.Version, cfg.TracingEnabled, api.RouterDeps{
		Ready:              deps,
		AuthService:        deps.AuthService,
		PKIService:         deps.PKIService,
		SecretsService:     deps.SecretsService,
		DatabaseService:    deps.DatabaseService,
		PolicyService:      deps.PolicyService,
		AuditExportService: deps.AuditExportService,
		InjectService:      deps.InjectService,
		BackupService:      deps.BackupService,
		TokenTTL:           deps.TokenTTL,
		HAEnabled:          deps.HAEnabled(),
		IsLeader:           deps.IsLeader,
		RateLimiter:        deps.RateLimiter,
		RequestSigning:     deps.RequestSigning,
	})

	app := &App{
		cfg:             cfg,
		log:             log,
		deps:            deps,
		tracingShutdown: traceShutdown,
		server: &http.Server{
			Addr:    cfg.HTTPAddr,
			Handler: router,
		},
	}
	return app, nil
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	errCh := make(chan error, 1)

	if a.deps.JobRunner != nil {
		a.deps.JobRunner.Start(ctx)
	}

	go func() {
		a.log.Info("starting knxvault", zap.String("addr", a.cfg.HTTPAddr), zap.String("version", a.cfg.Version))
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), a.cfg.ShutdownGrace)
		defer cancel()

		a.log.Info("shutting down")
		if err := a.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		a.shutdownObservability(shutdownCtx)
		return nil
	case err := <-errCh:
		a.shutdownObservability(context.Background())
		return err
	}
}

func (a *App) shutdownObservability(ctx context.Context) {
	if a.deps != nil {
		a.deps.Close()
	}
	if a.tracingShutdown != nil {
		_ = a.tracingShutdown(ctx)
	}
}
