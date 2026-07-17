// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/kubenexis/knxvault/internal/acme"
	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/controllers"
	"github.com/kubenexis/knxvault/internal/operator/vaultiface"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}

// Config holds operator runtime configuration.
type Config struct {
	VaultAddr   string
	VaultToken  string
	K8sRole     string
	SATokenPath string
	MetricsAddr string
	ProbeAddr   string
	IngressShim bool
	GatewayShim bool
	// ACMEHTTP01Addr when set serves /.well-known/acme-challenge/ for HTTP-01.
	ACMEHTTP01Addr string
	LeaderElect    bool
	LeaderElectID  string
	LeaderElectNS  string
}

// ConfigFromEnv loads configuration from environment.
func ConfigFromEnv() Config {
	return Config{
		VaultAddr:      envOr("KNXVAULT_ADDR", "http://knxvault.knxvault.svc:8200"),
		VaultToken:     strings.TrimSpace(os.Getenv("KNXVAULT_TOKEN")),
		K8sRole:        envOr("KNXVAULT_K8S_ROLE", "knxvault-operator"),
		SATokenPath:    envOr("KNXVAULT_SA_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		MetricsAddr:    envOr("KNXVAULT_OPERATOR_METRICS_ADDR", ":8080"),
		ProbeAddr:      envOr("KNXVAULT_OPERATOR_PROBE_ADDR", ":8081"),
		IngressShim:    strings.EqualFold(os.Getenv("KNXVAULT_OPERATOR_INGRESS_SHIM"), "true"),
		GatewayShim:    strings.EqualFold(os.Getenv("KNXVAULT_OPERATOR_GATEWAY_SHIM"), "true"),
		ACMEHTTP01Addr: strings.TrimSpace(os.Getenv("KNXVAULT_ACME_HTTP01_ADDR")),
		LeaderElect:    !strings.EqualFold(os.Getenv("KNXVAULT_OPERATOR_LEADER_ELECT"), "false"),
		LeaderElectID:  envOr("KNXVAULT_OPERATOR_LEADER_ELECT_ID", "knxvault-operator"),
		LeaderElectNS:  envOr("KNXVAULT_OPERATOR_LEADER_ELECT_NAMESPACE", "knxvault"),
	}
}

// Run starts the controller-runtime manager and all reconcilers.
func Run() error {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	cfg := ConfigFromEnv()
	if cfg.VaultToken == "" {
		if t := readTokenFile(envOr("KNXVAULT_TOKEN_FILE", "")); t != "" {
			cfg.VaultToken = t
		}
	}
	// Allow SA-only when token file will be read by HTTPAPI; still need either static token or SA file.
	if cfg.VaultToken == "" {
		if _, err := os.Stat(cfg.SATokenPath); err != nil {
			return fmt.Errorf("KNXVAULT_TOKEN / KNXVAULT_TOKEN_FILE or in-cluster SA token required")
		}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: cfg.MetricsAddr,
		},
		HealthProbeBindAddress:        cfg.ProbeAddr,
		LeaderElection:                cfg.LeaderElect,
		LeaderElectionID:              cfg.LeaderElectID,
		LeaderElectionNamespace:       cfg.LeaderElectNS,
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		return fmt.Errorf("manager: %w", err)
	}

	vault := vaultiface.NewHTTPWithSA(cfg.VaultAddr, cfg.VaultToken, cfg.K8sRole, cfg.SATokenPath)

	// W50-07: process-wide HTTP-01 challenge presenter + optional listener.
	if cfg.ACMEHTTP01Addr != "" {
		controllers.SharedHTTP01 = acme.NewMemoryHTTP01()
		go func() {
			srv := &http.Server{
				Addr:              cfg.ACMEHTTP01Addr,
				Handler:           controllers.SharedHTTP01,
				ReadHeaderTimeout: 10 * time.Second,
			}
			ctrl.Log.Info("ACME HTTP-01 solver listening", "addr", cfg.ACMEHTTP01Addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				ctrl.Log.Error(err, "ACME HTTP-01 listener failed")
			}
		}()
	}

	if err := (&controllers.CAReconciler{
		Client: mgr.GetClient(),
		Vault:  vault,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("ca controller: %w", err)
	}
	if err := (&controllers.CertificateReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Vault:  vault,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("certificate controller: %w", err)
	}
	if err := (&controllers.IssuerReconciler{
		Client: mgr.GetClient(),
		Vault:  vault,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("issuer controller: %w", err)
	}
	if err := (&controllers.ClusterIssuerReconciler{
		Client: mgr.GetClient(),
		Vault:  vault,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("clusterissuer controller: %w", err)
	}
	if err := (&controllers.CertificateRequestReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Vault:  vault,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("certificaterequest controller: %w", err)
	}
	if err := (&controllers.IngressReconciler{
		Client:  mgr.GetClient(),
		Scheme:  mgr.GetScheme(),
		Enabled: cfg.IngressShim,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("ingress controller: %w", err)
	}
	if cfg.GatewayShim {
		if err := (&controllers.GatewayReconciler{
			Client:  mgr.GetClient(),
			Scheme:  mgr.GetScheme(),
			Enabled: true,
		}).SetupWithManager(mgr); err != nil {
			// Gateway API CRDs may be absent on the cluster; do not block operator start.
			ctrl.Log.Info("gateway shim disabled (Gateway API not available)", "err", err.Error())
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return err
	}

	return mgr.Start(ctrl.SetupSignalHandler())
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func readTokenFile(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
