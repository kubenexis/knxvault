// Package metrics exposes Prometheus instrumentation (LLD observability).
package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	requestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "knxvault_http_requests_total",
			Help: "Total HTTP requests processed",
		},
		[]string{"method", "route", "status"},
	)
	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "knxvault_http_request_duration_seconds",
			Help:    "HTTP request latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "route"},
	)
	buildInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "knxvault_build_info",
			Help: "KNXVault build metadata (always 1)",
		},
		[]string{"version", "commit", "build_id"},
	)
	leaderGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "knxvault_leader",
			Help: "1 when this instance is the elected leader, 0 otherwise",
		},
	)
	leaderElectionGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "knxvault_leader_election_running",
			Help: "1 while the leader election background loop is active",
		},
	)
	activeLeasesGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "knxvault_active_leases",
			Help: "Number of active (non-revoked, non-expired) leases cluster-wide",
		},
	)
	rateLimitedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "knxvault_rate_limited_total",
			Help: "Total requests rejected by rate limiting",
		},
	)
	opensslBreakerOpen = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "knxvault_openssl_breaker_open",
			Help: "1 when the OpenSSL circuit breaker is open",
		},
	)
	csiMountRotationsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "knxvault_csi_mount_rotations_total",
			Help: "CSI mount operations that detected a KV version change",
		},
	)
	raftTLSEnabled = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "knxvault_raft_tls_enabled",
			Help: "1 when Raft peer mutual TLS is enabled",
		},
	)
	autoUnsealSuccessTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "knxvault_auto_unseal_success_total",
			Help: "Successful auto-unseal operations at startup",
		},
	)
	shamirUnsealShareTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "knxvault_shamir_unseal_share_total",
			Help: "Shamir unseal shares accepted",
		},
	)
	shamirUnsealSuccessTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "knxvault_shamir_unseal_total",
			Help: "Successful Shamir threshold unseals",
		},
	)
	tokensRevokedCascadeTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "knxvault_tokens_revoked_cascade_total",
			Help: "Child tokens revoked via cascade",
		},
	)
)

// SetBuildInfo records the running application build metadata.
func SetBuildInfo(version, commit, buildID string) {
	buildInfo.WithLabelValues(version, commit, buildID).Set(1)
}

// SetLeader records HA leadership status.
func SetLeader(isLeader bool) {
	if isLeader {
		leaderGauge.Set(1)
	} else {
		leaderGauge.Set(0)
	}
}

// SetLeaderElectionRunning records whether the leader election loop is active.
func SetLeaderElectionRunning(running bool) {
	if running {
		leaderElectionGauge.Set(1)
	} else {
		leaderElectionGauge.Set(0)
	}
}

// SetActiveLeasesGauge records the latest lease cleanup batch size.
func SetActiveLeasesGauge(count int) {
	activeLeasesGauge.Set(float64(count))
}

// IncCSIMountRotations increments CSI rotation detections.
func IncCSIMountRotations() {
	csiMountRotationsTotal.Inc()
}

// SetRaftTLSEnabled records whether Raft mTLS is active.
func SetRaftTLSEnabled(enabled bool) {
	if enabled {
		raftTLSEnabled.Set(1)
	} else {
		raftTLSEnabled.Set(0)
	}
}

// IncRateLimited increments the rate-limited request counter.
func IncRateLimited() {
	rateLimitedTotal.Inc()
}

// IncAutoUnsealSuccess increments auto-unseal success counter.
func IncAutoUnsealSuccess() { autoUnsealSuccessTotal.Inc() }

// IncShamirUnsealShare increments accepted Shamir share counter.
func IncShamirUnsealShare() { shamirUnsealShareTotal.Inc() }

// IncShamirUnsealSuccess increments successful Shamir unseal counter.
func IncShamirUnsealSuccess() { shamirUnsealSuccessTotal.Inc() }

// IncTokensRevokedCascade increments cascade revocation counter.
func IncTokensRevokedCascade(n int) {
	if n > 0 {
		tokensRevokedCascadeTotal.Add(float64(n))
	}
}

// SetOpenSSLBreakerOpen records OpenSSL circuit breaker state.
func SetOpenSSLBreakerOpen(open bool) {
	if open {
		opensslBreakerOpen.Set(1)
	} else {
		opensslBreakerOpen.Set(0)
	}
}

// Handler returns the Prometheus scrape handler.
func Handler() gin.HandlerFunc {
	return gin.WrapH(promhttp.Handler())
}

// Middleware records request counts and latency.
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		route := c.FullPath()
		if route == "" {
			route = "unknown"
		}
		status := strconv.Itoa(c.Writer.Status())
		method := c.Request.Method

		requestsTotal.WithLabelValues(method, route, status).Inc()
		requestDuration.WithLabelValues(method, route).Observe(time.Since(start).Seconds())
	}
}
