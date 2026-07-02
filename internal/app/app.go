// Package app bootstraps and runs the KNXVault HTTP server.
package app

import (
	"context"
	"fmt"
	"net/http"

	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/api"
	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/crypto/tlsconfig"
	"github.com/kubenexis/knxvault/internal/infra/tracing"
	"github.com/kubenexis/knxvault/internal/version"
)

// App owns the HTTP server lifecycle.
type App struct {
	cfg             config.Config
	log             *zap.Logger
	deps            *Dependencies
	server          *http.Server
	tracingShutdown func(context.Context) error
	tlsEnabled      bool
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

	tlsCfg, err := tlsconfig.LoadServerTLS(tlsconfig.ServerConfig{
		CertFile:     cfg.TLSCertFile,
		KeyFile:      cfg.TLSKeyFile,
		MTLSRequired: cfg.MTLSRequired,
		CAFile:       cfg.MTLSCAFile,
	})
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}

	var raftMembership handlers.RaftMembership
	if deps.Raft != nil {
		raftMembership = deps.Raft.Client
	}
	router := api.NewRouter(log, cfg.Version, cfg.TracingEnabled, api.RouterDeps{
		Ready:                deps,
		Seal:                 deps.Seal,
		MasterKey:            deps.MasterKey,
		MasterKeyService:     deps.MasterKeyService,
		RaftMembership:       raftMembership,
		CORSAllowedOrigins:   cfg.CORSAllowedOrigins,
		MTLSRequired:         cfg.MTLSRequired,
		OpenSSL:              deps.OpenSSL,
		AuthService:          deps.AuthService,
		PKIService:           deps.PKIService,
		SecretsService:       deps.SecretsService,
		DatabaseService:      deps.DatabaseService,
		SSHService:           deps.SSHService,
		PolicyService:        deps.PolicyService,
		RotationService:      deps.RotationService,
		OrchestrationService: deps.OrchestrationService,
		LeaseService:         deps.LeaseService,
		AuditPackService:     deps.AuditPackService,
		TenantMode:           cfg.TenantMode,
		MachineIdentitySvc:   deps.MachineIdentityService,
		AuthzAudit:           deps.AuthzAudit,
		AuditExportService:   deps.AuditExportService,
		InjectService:        deps.InjectService,
		BackupService:        deps.BackupService,
		ExposureSigningKey:   cfg.ExposureSigningKey,
		ExposureAutoRevoke:   cfg.ExposureAutoRevoke,
		ExposureWebhook:      deps.ExposureWebhook,
		TokenTTL:             deps.TokenTTL,
		HAStatus:             deps,
		IsLeader:             deps.IsLeader,
		RateLimiter:          deps.RateLimiter,
		AuthLoginLimiter:     deps.AuthLoginLimiter,
		TokenCreateLimiter:   deps.TokenCreateLimiter,
		RequestSigning:       deps.RequestSigning,
	})

	server := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: router,
	}
	if tlsCfg != nil {
		server.TLSConfig = tlsCfg
	}

	app := &App{
		cfg:             cfg,
		log:             log,
		deps:            deps,
		tracingShutdown: traceShutdown,
		server:          server,
		tlsEnabled:      tlsCfg != nil,
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
		fields := append([]zap.Field{zap.String("addr", a.cfg.HTTPAddr)}, version.ZapFields()...)
		a.log.Info("starting knxvault", fields...)
		var err error
		if a.tlsEnabled {
			err = a.server.ListenAndServeTLS(a.cfg.TLSCertFile, a.cfg.TLSKeyFile)
		} else {
			err = a.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
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
