// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package doctor runs deployment health and configuration diagnostics for KNXVault.
package doctor

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/kubenexis/knxvault/pkg/client"
)

// Status is the outcome of a single diagnostic check.
type Status string

const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusSkip Status = "skip"
)

// Check is one diagnostic result.
type Check struct {
	ID      string `json:"id"`
	Status  Status `json:"status"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// Report aggregates all checks for a doctor run.
type Report struct {
	Addr    string  `json:"addr"`
	Checks  []Check `json:"checks"`
	OK      int     `json:"ok"`
	Warn    int     `json:"warn"`
	Fail    int     `json:"fail"`
	Skip    int     `json:"skip"`
	Healthy bool    `json:"healthy"`
	Version string  `json:"version,omitempty"`
}

// Config captures local CLI settings used for diagnostics.
type Config struct {
	Addr       string
	Token      string
	ConfigFile string
	// Profile is "lab" (default) or "production" (W62-03 / W75).
	Profile string
	// MetricsAddr optional dedicated metrics URL for production checks.
	MetricsAddr string
	// Feature gate expectations (M-DTP-2 / W90-24). Empty strings skip checks.
	// Values: "true"/"false" (or "enabled"/"disabled") for OIDC, LDAP, audit forward, ACME.
	AuthOIDCEnabled     string
	AuthLDAPEnabled     string
	AuditForwardEnabled string
	ACMERelatedEnabled  string
	// RequestSigningKey when set indicates signing is configured (W86-11).
	RequestSigningKey string
}

// Runner executes doctor checks against a KNXVault deployment.
type Runner struct {
	Client *client.Client
	Config Config
}

// Run executes all diagnostics and returns a report. Healthy is false when any check fails.
func (r *Runner) Run(ctx context.Context) *Report {
	report := &Report{Addr: r.Config.Addr}
	r.checkCLIConfig(report)
	r.checkServer(ctx, report)
	r.checkAuth(ctx, report)
	r.checkProductionProfile(report)
	r.finalize(report)
	return report
}

func (r *Runner) checkProductionProfile(report *Report) {
	profile := strings.ToLower(strings.TrimSpace(r.Config.Profile))
	if profile != "production" && profile != "prod" {
		// W80-07: lab is the process default — warn when doctoring a non-loopback API.
		addr := strings.TrimSpace(r.Config.Addr)
		if u, err := url.Parse(addr); err == nil && u.Hostname() != "" && !isLoopbackHost(u.Hostname()) {
			report.add(Check{
				ID:      "profile.mode",
				Status:  StatusWarn,
				Message: "Doctor profile is lab; production deployments should use --profile production",
				Detail:  "Server should set KNXVAULT_SECURITY_PROFILE=production (fail-closed TLS, unseal CIDRs, metrics bearer, no coarse PKI write)",
			})
		} else {
			report.add(Check{
				ID:      "profile.mode",
				Status:  StatusSkip,
				Message: "Production profile checks skipped",
				Detail:  "Pass --profile production for fail-closed Day-0 gate",
			})
		}
		return
	}
	// Production: HTTP is a hard fail (unless operator documents ingress TLS separately —
	// we still require https client URL for production doctor).
	addr := strings.TrimSpace(r.Config.Addr)
	if u, err := url.Parse(addr); err == nil && strings.EqualFold(u.Scheme, "http") {
		report.add(Check{
			ID:      "profile.production.tls",
			Status:  StatusFail,
			Message: "Production profile requires https:// API address",
			Detail:  "Use TLS to knxvault or https through ingress; lab may use http",
		})
	} else {
		report.add(Check{
			ID:      "profile.production.tls",
			Status:  StatusOK,
			Message: "Production API address uses TLS scheme",
		})
	}
	if strings.TrimSpace(r.Config.Token) == "" {
		report.add(Check{
			ID:      "profile.production.token",
			Status:  StatusFail,
			Message: "Production profile requires a client token for doctor",
		})
	} else {
		report.add(Check{
			ID:      "profile.production.token",
			Status:  StatusOK,
			Message: "Client token present for production checks",
		})
	}
	// Metrics: when dedicated addr set, note it; anonymous metrics without bearer cannot be verified from CLI alone.
	if strings.TrimSpace(r.Config.MetricsAddr) != "" {
		report.add(Check{
			ID:      "profile.production.metrics_addr",
			Status:  StatusOK,
			Message: "Dedicated metrics address configured for scrape plane",
			Detail:  r.Config.MetricsAddr,
		})
	} else {
		report.add(Check{
			ID:      "profile.production.metrics_addr",
			Status:  StatusWarn,
			Message: "No dedicated metrics address (metrics may share API port)",
			Detail:  "Set KNXVAULT_METRICS_ADDR / --metrics-addr for CIS network split",
		})
	}
	// Fail if any prior server.sealed failed / sealed true is already handled.
	// Production gate: any fail already makes Healthy false; add explicit profile marker.
	report.add(Check{
		ID:      "profile.production.gate",
		Status:  StatusOK,
		Message: "Production profile doctor gate executed",
		Detail:  "Ensure vault process uses KNXVAULT_SECURITY_PROFILE=production and required secrets",
	})
	// W86-11: optional request signing guidance (local/env — not server-probed).
	signKey := strings.TrimSpace(r.Config.RequestSigningKey)
	if signKey == "" {
		signKey = strings.TrimSpace(os.Getenv("KNXVAULT_REQUEST_SIGNING_KEY"))
	}
	if signKey == "" {
		report.add(Check{
			ID:      "profile.production.request_signing",
			Status:  StatusWarn,
			Message: "Request signing key not visible to doctor (optional defense-in-depth)",
			Detail:  "Configure KNXVAULT_REQUEST_SIGNING_KEY on vault; production forces required=true when key is set",
		})
	} else {
		report.add(Check{
			ID:      "profile.production.request_signing",
			Status:  StatusOK,
			Message: "Request signing material present for doctor guidance",
		})
	}
	r.checkFeatureGates(report)
}

// checkFeatureGates reports M-DTP-2 feature gate posture (W90-24).
// When Profile is production and gate values are unset, warn that base should disable OIDC/LDAP/ACME/audit-forward.
func (r *Runner) checkFeatureGates(report *Report) {
	profile := strings.ToLower(strings.TrimSpace(r.Config.Profile))
	gates := []struct {
		id    string
		label string
		val   string
	}{
		{"feature.oidc", "OIDC auth", r.Config.AuthOIDCEnabled},
		{"feature.ldap", "LDAP auth", r.Config.AuthLDAPEnabled},
		{"feature.audit_forward", "audit forward", r.Config.AuditForwardEnabled},
		{"feature.acme", "ACME related", r.Config.ACMERelatedEnabled},
	}
	anySet := false
	for _, g := range gates {
		if strings.TrimSpace(g.val) != "" {
			anySet = true
			break
		}
	}
	if !anySet {
		if profile == "production" || profile == "prod" {
			report.add(Check{
				ID:      "feature.gates",
				Status:  StatusWarn,
				Message: "Feature gate posture not provided to doctor",
				Detail:  "For base/airgap production set KNXVAULT_AUTH_OIDC_ENABLED=false, AUTH_LDAP_ENABLED=false, AUDIT_FORWARD_ENABLED=false, ACME_RELATED_ENABLED=false (or pass matching --feature-* flags)",
			})
		}
		return
	}
	for _, g := range gates {
		v := strings.ToLower(strings.TrimSpace(g.val))
		if v == "" {
			continue
		}
		enabled := v == "true" || v == "1" || v == "enabled" || v == "on"
		disabled := v == "false" || v == "0" || v == "disabled" || v == "off"
		if !enabled && !disabled {
			report.add(Check{
				ID:      g.id,
				Status:  StatusWarn,
				Message: g.label + " gate value not recognized",
				Detail:  g.val,
			})
			continue
		}
		if profile == "production" || profile == "prod" {
			if enabled {
				report.add(Check{
					ID:      g.id,
					Status:  StatusWarn,
					Message: g.label + " is enabled (add-on surface on production profile)",
					Detail:  "Base airgap core should disable add-on auth/ACME/forward; enable only on platform-edge instances",
				})
			} else {
				report.add(Check{
					ID:      g.id,
					Status:  StatusOK,
					Message: g.label + " disabled (base fail-closed)",
				})
			}
			continue
		}
		// Lab / unspecified profile: report posture as OK info.
		state := "disabled"
		if enabled {
			state = "enabled"
		}
		report.add(Check{
			ID:      g.id,
			Status:  StatusOK,
			Message: g.label + " " + state,
		})
	}
}

func (r *Runner) checkCLIConfig(report *Report) {
	addr := strings.TrimSpace(r.Config.Addr)
	if addr == "" {
		report.add(Check{
			ID:      "cli.config.addr",
			Status:  StatusFail,
			Message: "API address is not configured",
			Detail:  "Set --addr, KNXVAULT_ADDR, or addr in ~/.knxvault/config.yaml",
		})
		return
	}

	parsed, err := url.Parse(addr)
	if err != nil || parsed.Host == "" {
		report.add(Check{
			ID:      "cli.config.addr",
			Status:  StatusFail,
			Message: "API address is invalid",
			Detail:  addr,
		})
		return
	}

	if addr == "http://localhost:8200" {
		report.add(Check{
			ID:      "cli.config.addr",
			Status:  StatusWarn,
			Message: "Using default local API address",
			Detail:  addr,
		})
	} else {
		report.add(Check{
			ID:      "cli.config.addr",
			Status:  StatusOK,
			Message: "API address configured",
			Detail:  addr,
		})
	}

	if strings.EqualFold(parsed.Scheme, "http") {
		report.add(Check{
			ID:      "cli.config.tls",
			Status:  StatusWarn,
			Message: "API traffic is not encrypted (http)",
			Detail:  "Use https:// in production deployments",
		})
	} else {
		report.add(Check{
			ID:      "cli.config.tls",
			Status:  StatusOK,
			Message: "API address uses TLS",
		})
	}

	if strings.TrimSpace(r.Config.Token) == "" {
		report.add(Check{
			ID:      "cli.config.token",
			Status:  StatusWarn,
			Message: "No client token configured",
			Detail:  "Set --token, KNXVAULT_TOKEN, or token in ~/.knxvault/config.yaml",
		})
	} else {
		report.add(Check{
			ID:      "cli.config.token",
			Status:  StatusOK,
			Message: "Client token configured",
		})
	}

	if r.Config.ConfigFile != "" {
		report.add(Check{
			ID:      "cli.config.file",
			Status:  StatusOK,
			Message: "CLI config file loaded",
			Detail:  r.Config.ConfigFile,
		})
	}
}

func (r *Runner) checkServer(ctx context.Context, report *Report) {
	health, err := r.Client.Health(ctx)
	if err != nil {
		report.add(Check{
			ID:      "server.connectivity",
			Status:  StatusFail,
			Message: "Cannot reach KNXVault API",
			Detail:  err.Error(),
		})
		report.add(Check{
			ID:      "server.health",
			Status:  StatusSkip,
			Message: "Skipped because API is unreachable",
		})
		report.add(Check{
			ID:      "server.readiness",
			Status:  StatusSkip,
			Message: "Skipped because API is unreachable",
		})
		report.add(Check{
			ID:      "server.sealed",
			Status:  StatusSkip,
			Message: "Skipped because API is unreachable",
		})
		report.add(Check{
			ID:      "server.raft",
			Status:  StatusSkip,
			Message: "Skipped because API is unreachable",
		})
		report.add(Check{
			ID:      "server.ha.leadership",
			Status:  StatusSkip,
			Message: "Skipped because API is unreachable",
		})
		report.add(Check{
			ID:      "server.metrics",
			Status:  StatusSkip,
			Message: "Skipped because API is unreachable",
		})
		return
	}

	report.add(Check{
		ID:      "server.connectivity",
		Status:  StatusOK,
		Message: "API is reachable",
	})
	report.Version = health.Version

	if health.Status == "healthy" {
		report.add(Check{
			ID:      "server.health",
			Status:  StatusOK,
			Message: fmt.Sprintf("Service is healthy (version %s)", health.Version),
		})
	} else {
		report.add(Check{
			ID:      "server.health",
			Status:  StatusFail,
			Message: fmt.Sprintf("Unexpected health status: %s", health.Status),
		})
	}

	ready, status, err := r.Client.ProbeReady(ctx)
	if err != nil {
		report.add(Check{
			ID:      "server.readiness",
			Status:  StatusFail,
			Message: "Readiness probe failed",
			Detail:  err.Error(),
		})
	} else if status == 200 && ready.Status == "ready" {
		report.add(Check{
			ID:      "server.readiness",
			Status:  StatusOK,
			Message: "Service is ready to accept traffic",
		})
	} else {
		report.add(Check{
			ID:      "server.readiness",
			Status:  StatusFail,
			Message: fmt.Sprintf("Service is not ready (status %s, HTTP %d)", ready.Status, status),
		})
	}

	statusBody := ready
	if statusBody == nil {
		statusBody = health
	}
	r.checkSeal(report, statusBody)
	r.checkRaft(report, statusBody)
	r.checkHALeadership(report, statusBody)
	r.checkMetrics(ctx, report)
}

func (r *Runner) checkSeal(report *Report, status *client.ReadyResponse) {
	if status == nil || status.Sealed == nil {
		report.add(Check{
			ID:      "server.sealed",
			Status:  StatusSkip,
			Message: "Seal status not reported by server",
		})
		return
	}
	if *status.Sealed {
		report.add(Check{
			ID:      "server.sealed",
			Status:  StatusFail,
			Message: "Vault is sealed",
			Detail:  "Mutating operations are blocked until unsealed",
		})
		return
	}
	report.add(Check{
		ID:      "server.sealed",
		Status:  StatusOK,
		Message: "Vault is unsealed",
	})
}

func (r *Runner) checkRaft(report *Report, status *client.ReadyResponse) {
	if status == nil || !status.RaftEnabled {
		report.add(Check{
			ID:      "server.raft",
			Status:  StatusOK,
			Message: "Raft replication is not enabled",
		})
		return
	}
	if status.RaftReady == nil {
		report.add(Check{
			ID:      "server.raft",
			Status:  StatusWarn,
			Message: "Raft is enabled but readiness was not reported",
		})
		return
	}
	if *status.RaftReady {
		report.add(Check{
			ID:      "server.raft",
			Status:  StatusOK,
			Message: "Raft cluster is ready",
		})
		return
	}
	report.add(Check{
		ID:      "server.raft",
		Status:  StatusFail,
		Message: "Raft is enabled but not ready",
		Detail:  "Check peer connectivity and leader election",
	})
}

func (r *Runner) checkHALeadership(report *Report, status *client.ReadyResponse) {
	if status == nil || !status.HAEnabled {
		report.add(Check{
			ID:      "server.ha.leadership",
			Status:  StatusOK,
			Message: "HA leader election is not enabled",
		})
		return
	}
	if status.Leader == nil {
		report.add(Check{
			ID:      "server.ha.leadership",
			Status:  StatusWarn,
			Message: "HA is enabled but leader status was not reported",
		})
		return
	}
	if *status.Leader {
		report.add(Check{
			ID:      "server.ha.leadership",
			Status:  StatusOK,
			Message: "This node is the HA leader",
		})
		return
	}
	report.add(Check{
		ID:      "server.ha.leadership",
		Status:  StatusWarn,
		Message: "This node is not the HA leader",
		Detail:  "Write traffic should target the leader",
	})
}

func (r *Runner) checkMetrics(ctx context.Context, report *Report) {
	code, err := r.Client.ProbeMetrics(ctx)
	if err != nil {
		report.add(Check{
			ID:      "server.metrics",
			Status:  StatusWarn,
			Message: "Metrics endpoint is unreachable",
			Detail:  err.Error(),
		})
		return
	}
	if code >= 200 && code < 300 {
		report.add(Check{
			ID:      "server.metrics",
			Status:  StatusOK,
			Message: "Metrics endpoint is responding",
		})
		return
	}
	report.add(Check{
		ID:      "server.metrics",
		Status:  StatusWarn,
		Message: fmt.Sprintf("Metrics endpoint returned HTTP %d", code),
	})
}

func (r *Runner) checkAuth(ctx context.Context, report *Report) {
	if strings.TrimSpace(r.Config.Token) == "" {
		report.add(Check{
			ID:      "auth.token",
			Status:  StatusSkip,
			Message: "Skipped because no client token is configured",
		})
		return
	}

	caps, err := r.Client.Capabilities(ctx)
	if err != nil {
		if apiErr, ok := err.(*client.APIError); ok && (apiErr.Status == 401 || apiErr.Status == 403) {
			report.add(Check{
				ID:      "auth.token",
				Status:  StatusFail,
				Message: "Client token is invalid or expired",
				Detail:  apiErr.Message,
			})
			return
		}
		report.add(Check{
			ID:      "auth.token",
			Status:  StatusFail,
			Message: "Token validation failed",
			Detail:  err.Error(),
		})
		return
	}

	if len(caps.Capabilities) == 0 {
		report.add(Check{
			ID:      "auth.token",
			Status:  StatusWarn,
			Message: "Token is valid but has no capabilities",
		})
		return
	}

	report.add(Check{
		ID:      "auth.token",
		Status:  StatusOK,
		Message: fmt.Sprintf("Client token is valid (%d capabilities)", len(caps.Capabilities)),
	})
}

func (report *Report) add(check Check) {
	report.Checks = append(report.Checks, check)
	switch check.Status {
	case StatusOK:
		report.OK++
	case StatusWarn:
		report.Warn++
	case StatusFail:
		report.Fail++
	case StatusSkip:
		report.Skip++
	}
}

func (r *Runner) finalize(report *Report) {
	report.Healthy = report.Fail == 0
}

// isLoopbackHost reports whether host is a loopback name/address (W80-07 doctor warn gate).
func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	switch h {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}
	return strings.HasPrefix(h, "127.")
}
