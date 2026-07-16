package operator

import (
	"fmt"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

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
	MetricsAddr string
	ProbeAddr   string
	IngressShim bool
}

// ConfigFromEnv loads configuration from environment.
func ConfigFromEnv() Config {
	return Config{
		VaultAddr:   envOr("KNXVAULT_ADDR", "http://knxvault.knxvault.svc:8200"),
		VaultToken:  strings.TrimSpace(os.Getenv("KNXVAULT_TOKEN")),
		MetricsAddr: envOr("KNXVAULT_OPERATOR_METRICS_ADDR", ":8080"),
		ProbeAddr:   envOr("KNXVAULT_OPERATOR_PROBE_ADDR", ":8081"),
		IngressShim: strings.EqualFold(os.Getenv("KNXVAULT_OPERATOR_INGRESS_SHIM"), "true"),
	}
}

// Run starts the controller-runtime manager and all reconcilers (W30-01…W30-06, W30-10).
func Run() error {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	cfg := ConfigFromEnv()
	if cfg.VaultToken == "" {
		// Allow empty for in-cluster SA login path later; for now require token or fail clearly.
		if t := readTokenFile(envOr("KNXVAULT_TOKEN_FILE", "")); t != "" {
			cfg.VaultToken = t
		}
	}
	if cfg.VaultToken == "" {
		return fmt.Errorf("KNXVAULT_TOKEN or KNXVAULT_TOKEN_FILE is required")
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: cfg.MetricsAddr,
		},
		HealthProbeBindAddress: cfg.ProbeAddr,
		LeaderElection:         false,
	})
	if err != nil {
		return fmt.Errorf("manager: %w", err)
	}

	vault := vaultiface.NewHTTP(cfg.VaultAddr, cfg.VaultToken)

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
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("issuer controller: %w", err)
	}
	if err := (&controllers.ClusterIssuerReconciler{
		Client: mgr.GetClient(),
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
	b, err := os.ReadFile(path) //nolint:gosec // path from env for k8s secret mount
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
