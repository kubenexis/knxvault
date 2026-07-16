// Package metrics exposes Prometheus instrumentation (LLD observability).
package metrics

import (
	"crypto/subtle"
	"net/http"
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
	leaderElectionRunningGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "knxvault_leader_election_running",
			Help: "1 while the leader election goroutine is active, 0 after unexpected exit",
		},
	)
	activeLeasesGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "knxvault_active_leases",
			Help: "Number of leases processed in the most recent cleanup cycle",
		},
	)
	rateLimitedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "knxvault_rate_limited_total",
			Help: "Total requests rejected by rate limiting",
		},
	)
	authLoginThrottledTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "knxvault_auth_login_throttled_total",
			Help: "Auth login requests rejected by throttling",
		},
	)
	tokenCreateThrottledTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "knxvault_token_create_throttled_total",
			Help: "Token create/delegate requests rejected by throttling",
		},
	)
	leasesByEngine = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "knxvault_leases_by_engine",
			Help: "Active leases by engine and role",
		},
		[]string{"engine", "role"},
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
	auditForwardSentTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "knxvault_audit_forward_sent_total",
			Help: "Audit entries successfully forwarded to SIEM",
		},
	)
	auditForwardDroppedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "knxvault_audit_forward_dropped_total",
			Help: "Audit entries dropped when forward queue is full",
		},
	)
	auditForwardFailedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "knxvault_audit_forward_failed_total",
			Help: "Audit forward HTTP failures",
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
		leaderElectionRunningGauge.Set(1)
	} else {
		leaderElectionRunningGauge.Set(0)
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

// IncAuthLoginThrottled increments auth login throttle counter (W43-03).
func IncAuthLoginThrottled() { authLoginThrottledTotal.Inc() }

// IncTokenCreateThrottled increments token create throttle counter (W43-05).
func IncTokenCreateThrottled() { tokenCreateThrottledTotal.Inc() }

// SetLeasesByEngine records per-role active lease counts (W42-07).
func SetLeasesByEngine(engine, role string, count int) {
	leasesByEngine.WithLabelValues(engine, role).Set(float64(count))
}

// SetOpenSSLBreakerOpen records OpenSSL circuit breaker state.
func SetOpenSSLBreakerOpen(open bool) {
	if open {
		opensslBreakerOpen.Set(1)
	} else {
		opensslBreakerOpen.Set(0)
	}
}

// IncAuditForwardSent increments successful audit SIEM forwards (W50-27).
func IncAuditForwardSent() { auditForwardSentTotal.Inc() }

// IncAuditForwardDropped increments dropped audit SIEM forwards (queue full).
func IncAuditForwardDropped() { auditForwardDroppedTotal.Inc() }

// IncAuditForwardFailed increments failed audit SIEM HTTP posts.
func IncAuditForwardFailed() { auditForwardFailedTotal.Inc() }

// Handler returns the Prometheus scrape handler.
func Handler() gin.HandlerFunc {
	return gin.WrapH(promhttp.Handler())
}

// HandlerWithAuth returns a metrics handler that requires a bearer token when token is non-empty (W50-19).
func HandlerWithAuth(token string) gin.HandlerFunc {
	inner := promhttp.Handler()
	if token == "" {
		return gin.WrapH(inner)
	}
	want := "Bearer " + token
	return func(c *gin.Context) {
		got := c.GetHeader("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(c.Writer, c.Request)
	}
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
