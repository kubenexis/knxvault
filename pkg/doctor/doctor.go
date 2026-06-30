// Package doctor runs deployment health and configuration diagnostics for KNXVault.
package doctor

import (
	"context"
	"fmt"
	"net/url"
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
	r.finalize(report)
	return report
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