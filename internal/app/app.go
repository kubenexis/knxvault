// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package app bootstraps and runs the KNXVault HTTP server.
package app

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/api"
	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/crypto/tlsconfig"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
	"github.com/kubenexis/knxvault/internal/infra/tracing"
	"github.com/kubenexis/knxvault/internal/version"
)

// App owns the HTTP server lifecycle.
type App struct {
	cfg             config.Config
	log             *zap.Logger
	deps            *Dependencies
	server          *http.Server
	metricsServer   *http.Server
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
	// Dedicated metrics listener when MetricsAddr is set (W75-03); otherwise /metrics on API.
	metricsDedicated := strings.TrimSpace(cfg.MetricsAddr) != ""
	router := api.NewRouter(log, cfg.Version, cfg.TracingEnabled, api.RouterDeps{
		Ready:                deps,
		Seal:                 deps.Seal,
		MasterKey:            deps.MasterKey,
		MasterKeyService:     deps.MasterKeyService,
		RaftMembership:       raftMembership,
		CORSAllowedOrigins:   cfg.CORSAllowedOrigins,
		MTLSRequired:         cfg.MTLSRequired,
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
		CubbyholeService:     deps.CubbyholeService,
		WrappingService:      deps.WrappingService,
		TransitService:       deps.TransitService,
		IdentityService:      deps.IdentityService,
		AuthzAudit:           deps.AuthzAudit,
		AuditExportService:   deps.AuditExportService,
		InjectService:        deps.InjectService,
		BackupService:        deps.BackupService,
		ExposureSigningKey:   cfg.ExposureSigningKey,
		ExposureAutoRevoke:   cfg.ExposureAutoRevoke,
		ExposurePathPrefixes: cfg.ExposurePathPrefixes,
		ExposureWebhook:      deps.ExposureWebhook,
		TokenTTL:             deps.TokenTTL,
		HAStatus:             deps,
		IsLeader:             deps.IsLeader,
		RateLimiter:          deps.RateLimiter,
		SharedRateLimiter:    deps.SharedRateLimiter,
		AuthLoginLimiter:     deps.AuthLoginLimiter,
		TokenCreateLimiter:   deps.TokenCreateLimiter,
		RequestSigning:       deps.RequestSigning,
		TrustedProxies:       cfg.TrustedProxies,
		MetricsBearerToken:   cfg.MetricsBearerToken,
		MetricsDedicatedOnly: metricsDedicated,
		UnsealAllowCIDRs:     cfg.UnsealAllowCIDRs,
		AllowCoarsePKIWrite:  cfg.AllowCoarsePKIWrite,
		// W80-06: share exposure replay with Valkey when configured (HA-safe).
		ExposureReplayStore: middleware.NewCacheExposureReplayStore(deps.CacheStore),
	})

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if tlsCfg != nil {
		server.TLSConfig = tlsCfg
	}

	var metricsServer *http.Server
	if metricsDedicated {
		mr := gin.New()
		mr.Use(gin.Recovery())
		mr.GET("/metrics", metrics.HandlerWithAuth(cfg.MetricsBearerToken))
		mr.GET("/health", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
		metricsServer = &http.Server{
			Addr:              cfg.MetricsAddr,
			Handler:           mr,
			ReadHeaderTimeout: 10 * time.Second,
		}
	}

	app := &App{
		cfg:             cfg,
		log:             log,
		deps:            deps,
		tracingShutdown: traceShutdown,
		server:          server,
		metricsServer:   metricsServer,
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

	if a.metricsServer != nil {
		go func() {
			a.log.Info("starting metrics listener", zap.String("addr", a.cfg.MetricsAddr))
			if err := a.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				a.log.Error("metrics server", zap.Error(err))
			}
		}()
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), a.cfg.ShutdownGrace)
		defer cancel()

		a.log.Info("shutting down")
		if err := a.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		if a.metricsServer != nil {
			_ = a.metricsServer.Shutdown(shutdownCtx)
		}
		a.shutdownObservability(shutdownCtx)
		return nil
	case err := <-errCh:
		if a.metricsServer != nil {
			_ = a.metricsServer.Shutdown(context.Background())
		}
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
