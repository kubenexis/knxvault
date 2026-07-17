// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package tracing configures OpenTelemetry distributed tracing.
package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/kubenexis/knxvault/internal/config"
)

// ShutdownFunc flushes and shuts down the tracer provider.
type ShutdownFunc func(context.Context) error

// Init configures the global tracer provider when tracing is enabled.
func Init(ctx context.Context, cfg config.Config) (ShutdownFunc, error) {
	if !cfg.TracingEnabled {
		return func(context.Context) error { return nil }, nil
	}

	opts := []otlptracehttp.Option{}
	if cfg.OTLPEndpoint != "" {
		opts = append(opts, otlptracehttp.WithEndpoint(cfg.OTLPEndpoint), otlptracehttp.WithInsecure())
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("knxvault"),
			semconv.ServiceVersion(cfg.Version),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("trace resource: %w", err)
	}

	ratio := cfg.TracingSampleRatio
	if ratio <= 0 {
		ratio = 1
	}
	if ratio > 1 {
		ratio = 1
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(ratio)),
	)
	otel.SetTracerProvider(provider)

	return provider.Shutdown, nil
}
