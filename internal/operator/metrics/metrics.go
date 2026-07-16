// Package metrics exports Prometheus metrics for the operator.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// IssuesTotal counts successful certificate issues.
	IssuesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "knxvault_operator_certificate_issues_total",
		Help: "Successful leaf certificate issues",
	})
	// RenewsTotal counts successful renewals.
	RenewsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "knxvault_operator_certificate_renews_total",
		Help: "Successful leaf certificate renewals",
	})
	// ErrorsTotal counts reconcile errors.
	ErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "knxvault_operator_reconcile_errors_total",
		Help: "Operator reconcile errors by controller",
	}, []string{"controller"})
	// CAReady is 1 when last CA reconcile succeeded (informational gauge set by tests/controllers).
	CAReady = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "knxvault_operator_ca_ready",
		Help: "1 if last CA status was Ready",
	})
)
