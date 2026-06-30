// Package k8s provides Kubernetes integrations (LLD §6.2 HA).
package k8s

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kubenexis/knxvault/internal/infra/hostidentity"
)

const (
	defaultK8sAPIHost = "https://kubernetes.default.svc"
	leaseAPIVersion   = "coordination.k8s.io/v1"
)

func defaultSATokenPath() string {
	return filepath.Join("/var", "run", "secrets", "kubernetes.io", "serviceaccount", "token")
}

func defaultSANamespacePath() string {
	return filepath.Join("/var", "run", "secrets", "kubernetes.io", "serviceaccount", "namespace")
}

// LeaderConfig configures Kubernetes Lease-based leader election.
type LeaderConfig struct {
	Namespace string
	LeaseName string
	Identity  string
	APIHost   string
	TokenPath string
}

// LeaderElector acquires a coordination.k8s.io Lease for HA background jobs.
type LeaderElector struct {
	cfg    LeaderConfig
	client *http.Client
	token  string
	mu     sync.RWMutex
	leader bool
}

// NewLeaderElector constructs a Kubernetes leader elector using the in-cluster API.
func NewLeaderElector(cfg LeaderConfig) (*LeaderElector, error) {
	if cfg.Namespace == "" {
		cfg.Namespace = "knxvault"
	}
	if cfg.LeaseName == "" {
		cfg.LeaseName = "knxvault-leader"
	}
	if cfg.Identity == "" {
		cfg.Identity = hostidentity.Hostname()
		if cfg.Identity == "" {
			cfg.Identity = "knxvault"
		}
	}
	if cfg.APIHost == "" {
		cfg.APIHost = defaultK8sAPIHost
	}
	if cfg.TokenPath == "" {
		cfg.TokenPath = defaultSATokenPath()
	}

	token, err := os.ReadFile(cfg.TokenPath)
	if err != nil {
		return nil, fmt.Errorf("read service account token: %w", err)
	}
	if cfg.Namespace == "knxvault" {
		if ns, err := os.ReadFile(defaultSANamespacePath()); err == nil {
			cfg.Namespace = string(bytes.TrimSpace(ns))
		}
	}

	return &LeaderElector{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		token:  string(bytes.TrimSpace(token)),
	}, nil
}

// Run participates in leader election until ctx is cancelled.
func (e *LeaderElector) Run(ctx context.Context, onLeadership func(ctx context.Context)) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var leadCancel context.CancelFunc
	for {
		select {
		case <-ctx.Done():
			if leadCancel != nil {
				leadCancel()
			}
			e.setLeader(false)
			return ctx.Err()
		case <-ticker.C:
			acquired, err := e.tryAcquire(ctx)
			if err != nil {
				e.setLeader(false)
				continue
			}
			if acquired {
				if leadCancel == nil {
					var leadCtx context.Context
					leadCtx, leadCancel = context.WithCancel(ctx)
					e.setLeader(true)
					go onLeadership(leadCtx)
				}
				continue
			}
			if leadCancel != nil {
				leadCancel()
				leadCancel = nil
			}
			e.setLeader(false)
		}
	}
}

// IsLeader reports whether this instance holds the lease.
func (e *LeaderElector) IsLeader() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.leader
}

func (e *LeaderElector) setLeader(leader bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.leader = leader
}

func (e *LeaderElector) tryAcquire(ctx context.Context) (bool, error) {
	lease, err := e.getLease(ctx)
	if err != nil {
		if err := e.createLease(ctx); err != nil {
			return false, err
		}
		return true, nil
	}

	now := time.Now().UTC()
	holder := ""
	if lease.Spec.HolderIdentity != nil {
		holder = *lease.Spec.HolderIdentity
	}
	renewTime := parseTime(lease.Spec.RenewTime)
	leaseDuration := 15 * time.Second
	if lease.Spec.LeaseDurationSeconds != nil && *lease.Spec.LeaseDurationSeconds > 0 {
		leaseDuration = time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second
	}

	if holder == e.cfg.Identity {
		lease.Spec.RenewTime = formatTime(now)
		if err := e.updateLease(ctx, lease); err != nil {
			return false, err
		}
		return true, nil
	}
	if holder != "" && renewTime.Add(leaseDuration).After(now) {
		return false, nil
	}

	lease.Spec.HolderIdentity = &e.cfg.Identity
	lease.Spec.RenewTime = formatTime(now)
	leaseDurationSeconds := int32(leaseDuration.Seconds())
	lease.Spec.LeaseDurationSeconds = &leaseDurationSeconds
	if err := e.updateLease(ctx, lease); err != nil {
		return false, err
	}
	return true, nil
}

type leaseObject struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Metadata   leaseMeta `json:"metadata"`
	Spec       leaseSpec `json:"spec"`
}

type leaseMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type leaseSpec struct {
	HolderIdentity       *string `json:"holderIdentity,omitempty"`
	LeaseDurationSeconds *int32  `json:"leaseDurationSeconds,omitempty"`
	AcquireTime          *string `json:"acquireTime,omitempty"`
	RenewTime            *string `json:"renewTime,omitempty"`
}

func (e *LeaderElector) leaseURL() string {
	return fmt.Sprintf("%s/apis/coordination.k8s.io/v1/namespaces/%s/leases/%s",
		e.cfg.APIHost, e.cfg.Namespace, e.cfg.LeaseName)
}

func (e *LeaderElector) getLease(ctx context.Context) (*leaseObject, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.leaseURL(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Accept", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("lease not found")
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get lease: status %d: %s", resp.StatusCode, string(body))
	}

	var lease leaseObject
	if err := json.NewDecoder(resp.Body).Decode(&lease); err != nil {
		return nil, err
	}
	return &lease, nil
}

func (e *LeaderElector) createLease(ctx context.Context) error {
	now := formatTime(time.Now().UTC())
	duration := int32(15)
	lease := leaseObject{
		APIVersion: leaseAPIVersion,
		Kind:       "Lease",
		Metadata: leaseMeta{
			Name:      e.cfg.LeaseName,
			Namespace: e.cfg.Namespace,
		},
		Spec: leaseSpec{
			HolderIdentity:       &e.cfg.Identity,
			LeaseDurationSeconds: &duration,
			AcquireTime:          now,
			RenewTime:            now,
		},
	}
	return e.putLease(ctx, lease, false)
}

func (e *LeaderElector) updateLease(ctx context.Context, lease *leaseObject) error {
	lease.APIVersion = leaseAPIVersion
	lease.Kind = "Lease"
	return e.putLease(ctx, *lease, true)
}

func (e *LeaderElector) putLease(ctx context.Context, lease leaseObject, update bool) error {
	payload, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	method := http.MethodPost
	url := fmt.Sprintf("%s/apis/coordination.k8s.io/v1/namespaces/%s/leases",
		e.cfg.APIHost, e.cfg.Namespace)
	if update {
		method = http.MethodPut
		url = e.leaseURL()
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("put lease: status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func formatTime(t time.Time) *string {
	formatted := t.Format(time.RFC3339Nano)
	return &formatted
}

func parseTime(raw *string) time.Time {
	if raw == nil || *raw == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, *raw)
	if err != nil {
		t, _ = time.Parse(time.RFC3339, *raw)
	}
	return t
}

// InClusterConfigAvailable reports whether the pod service account token exists.
func InClusterConfigAvailable() bool {
	_, err := os.Stat(filepath.Clean(defaultSATokenPath()))
	return err == nil
}
