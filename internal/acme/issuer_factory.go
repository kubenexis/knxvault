package acme

import (
	"fmt"
	"strings"
)

// SolverSpec configures challenge solvers from operator CRDs / env.
type SolverSpec struct {
	// HTTP01 enables in-memory (or shared) HTTP-01 presenter.
	HTTP01 bool
	// DNSProvider is "memory", "webhook", or "cloudflare".
	DNSProvider string
	// WebhookURL for DNSProvider=webhook.
	WebhookURL string
	// CloudflareToken / ZoneID for DNSProvider=cloudflare.
	CloudflareToken string
	CloudflareZone  string
}

// BuildSolvers constructs presenters from SolverSpec.
func BuildSolvers(spec SolverSpec) (HTTP01Presenter, DNS01Presenter, error) {
	var http01 HTTP01Presenter
	var dns01 DNS01Presenter
	if spec.HTTP01 {
		http01 = NewMemoryHTTP01()
	}
	switch strings.ToLower(strings.TrimSpace(spec.DNSProvider)) {
	case "", "none":
		// no DNS
	case "memory":
		dns01 = NewMemoryDNS01()
	case "webhook":
		if spec.WebhookURL == "" {
			return nil, nil, fmt.Errorf("webhook DNS requires URL")
		}
		dns01 = &WebhookDNS01{URL: spec.WebhookURL}
	case "cloudflare":
		if spec.CloudflareToken == "" {
			return nil, nil, fmt.Errorf("cloudflare DNS requires API token")
		}
		dns01 = &CloudflareDNS01{APIToken: spec.CloudflareToken, ZoneID: spec.CloudflareZone}
	default:
		return nil, nil, fmt.Errorf("unknown DNS provider %q", spec.DNSProvider)
	}
	return http01, dns01, nil
}

// NewIssuerFromKind returns SelfSigned or ACME Issuer.
func NewIssuerFromKind(kind string, cfg Config, solvers SolverSpec) (Issuer, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "selfsigned", "self-signed":
		return &SelfSignedIssuer{}, nil
	case "acme":
		http01, dns01, err := BuildSolvers(solvers)
		if err != nil {
			return nil, err
		}
		if http01 == nil && dns01 == nil {
			return nil, fmt.Errorf("acme issuer requires at least one solver (http-01 or dns-01)")
		}
		return NewClient(cfg, http01, dns01), nil
	default:
		return nil, fmt.Errorf("unknown issuer kind %q", kind)
	}
}
