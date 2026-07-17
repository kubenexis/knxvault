// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Profile is a portable ACME configuration (CLI / standalone).
type Profile struct {
	Name          string   `yaml:"profile"`
	DirectoryURL  string   `yaml:"directory_url"`
	Email         string   `yaml:"email"`
	AcceptTOS     bool     `yaml:"accept_tos"`
	AccountKey    string   `yaml:"account_key_file"`
	SkipTLSVerify bool     `yaml:"skip_tls_verify"`
	Challenges    []string `yaml:"challenges"`

	HTTP01 *ProfileHTTP01 `yaml:"http01"`
	DNS01  *ProfileDNS01  `yaml:"dns01"`

	Domains []ProfileDomain `yaml:"domains"`

	Delivery      ProfileDelivery `yaml:"delivery"`
	RenewBefore   string          `yaml:"renew_before"`
	PostRenewHook string          `yaml:"post_renew_hook"`
	StateFile     string          `yaml:"state_file"`
}

// ProfileHTTP01 configures host HTTP-01.
type ProfileHTTP01 struct {
	Mode       string `yaml:"mode"`
	ListenAddr string `yaml:"listen_addr"`
	Webroot    string `yaml:"webroot"`
}

// ProfileDNS01 configures DNS-01.
type ProfileDNS01 struct {
	Provider     string `yaml:"provider"`
	APIToken     string `yaml:"api_token"`
	APITokenFile string `yaml:"api_token_file"`
	ZoneID       string `yaml:"zone_id"`
	WebhookURL   string `yaml:"webhook_url"`
}

// ProfileDomain is one certificate request.
type ProfileDomain struct {
	Name string   `yaml:"name"`
	SANs []string `yaml:"sans"`
}

// ProfileDelivery is how certs are written.
type ProfileDelivery struct {
	Type     string `yaml:"type"`
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
}

// StagingDirectory is Let's Encrypt staging ACME directory.
const StagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

// LoadProfileYAML reads a Profile from path.
func LoadProfileYAML(path string) (*Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse acme profile: %w", err)
	}
	p.applyDefaults()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Profile) applyDefaults() {
	if p.DirectoryURL == "" {
		p.DirectoryURL = StagingDirectory // prefer staging for safety in examples
	}
	if p.Delivery.Type == "" {
		p.Delivery.Type = "files"
	}
	if p.HTTP01 != nil && p.HTTP01.Mode == "" {
		if p.HTTP01.Webroot != "" {
			p.HTTP01.Mode = "webroot"
		} else {
			p.HTTP01.Mode = "listen"
		}
	}
	if p.HTTP01 != nil && p.HTTP01.ListenAddr == "" {
		p.HTTP01.ListenAddr = ":80"
	}
	if p.AccountKey == "" {
		p.AccountKey = "account.key"
	}
	if p.StateFile == "" && p.Delivery.CertPath != "" {
		p.StateFile = p.Delivery.CertPath + ".acme-state.json"
	}
}

// Validate checks required fields and security guards.
func (p *Profile) Validate() error {
	if p == nil {
		return fmt.Errorf("profile is nil")
	}
	if !p.AcceptTOS {
		return fmt.Errorf("accept_tos must be true")
	}
	if strings.TrimSpace(p.Email) == "" {
		return fmt.Errorf("email is required")
	}
	if p.SkipTLSVerify && PublicLEHost(p.DirectoryURL) {
		return fmt.Errorf("skip_tls_verify is not allowed for public Let's Encrypt directories")
	}
	if !p.SkipTLSVerify {
		if err := ValidateDirectoryURL(p.DirectoryURL); err != nil {
			return fmt.Errorf("directory_url: %w", err)
		}
	}
	if len(p.Domains) == 0 {
		return fmt.Errorf("at least one domain is required")
	}
	for _, d := range p.Domains {
		if strings.TrimSpace(d.Name) == "" {
			return fmt.Errorf("domain name is required")
		}
	}
	if p.Delivery.Type == "files" || p.Delivery.Type == "" {
		if p.Delivery.CertPath == "" || p.Delivery.KeyPath == "" {
			return fmt.Errorf("delivery.cert_path and delivery.key_path are required")
		}
	}
	hasHTTP := p.HTTP01 != nil
	hasDNS := p.DNS01 != nil && strings.TrimSpace(p.DNS01.Provider) != ""
	if !hasHTTP && !hasDNS {
		return fmt.Errorf("configure http01 and/or dns01")
	}
	return nil
}

// RenewBeforeDuration parses renew_before (default 720h).
func (p *Profile) RenewBeforeDuration() time.Duration {
	if p == nil || strings.TrimSpace(p.RenewBefore) == "" {
		return DefaultRenewBefore
	}
	d, err := time.ParseDuration(p.RenewBefore)
	if err != nil || d <= 0 {
		return DefaultRenewBefore
	}
	return d
}

// ToConfig builds Config; accountKey may be nil (caller sets after LoadOrCreate).
func (p *Profile) ToConfig(accountKey crypto.Signer) Config {
	cfg := Config{
		DirectoryURL:  p.DirectoryURL,
		Email:         p.Email,
		AcceptTOS:     p.AcceptTOS,
		SkipTLSVerify: p.SkipTLSVerify,
		AccountKey:    accountKey,
	}
	for _, c := range p.Challenges {
		switch strings.ToLower(strings.TrimSpace(c)) {
		case "http-01", "http01":
			cfg.Challenges = append(cfg.Challenges, ChallengeHTTP01)
		case "dns-01", "dns01":
			cfg.Challenges = append(cfg.Challenges, ChallengeDNS01)
		}
	}
	return cfg
}

// BuildSolversFromProfile constructs presenters from profile HTTP/DNS sections.
func BuildSolversFromProfile(p *Profile) (HTTP01Presenter, DNS01Presenter, *MemoryHTTP01, error) {
	if p == nil {
		return nil, nil, nil, fmt.Errorf("profile is nil")
	}
	var http01 HTTP01Presenter
	var mem *MemoryHTTP01
	if p.HTTP01 != nil {
		switch strings.ToLower(p.HTTP01.Mode) {
		case "webroot":
			if p.HTTP01.Webroot == "" {
				return nil, nil, nil, fmt.Errorf("http01.webroot is required for webroot mode")
			}
			http01 = &WebrootHTTP01{Root: p.HTTP01.Webroot}
		default: // listen
			mem = NewMemoryHTTP01()
			http01 = mem
		}
	}
	var dns01 DNS01Presenter
	if p.DNS01 != nil && strings.TrimSpace(p.DNS01.Provider) != "" {
		token := p.DNS01.APIToken
		if token == "" && p.DNS01.APITokenFile != "" {
			b, err := os.ReadFile(p.DNS01.APITokenFile)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("dns01 api_token_file: %w", err)
			}
			token = strings.TrimSpace(string(b))
		}
		spec := SolverSpec{
			DNSProvider:     p.DNS01.Provider,
			WebhookURL:      p.DNS01.WebhookURL,
			CloudflareToken: token,
			CloudflareZone:  p.DNS01.ZoneID,
		}
		_, d, err := BuildSolvers(spec)
		if err != nil {
			return nil, nil, nil, err
		}
		dns01 = d
	}
	if http01 == nil && dns01 == nil {
		return nil, nil, nil, fmt.Errorf("no ACME solvers configured")
	}
	return http01, dns01, mem, nil
}

// PrimaryOrder builds OrderRequest from the first domain entry.
func (p *Profile) PrimaryOrder() OrderRequest {
	d := p.Domains[0]
	sans := append([]string{}, d.SANs...)
	return OrderRequest{
		CommonName: d.Name,
		DNSNames:   uniqueNames(d.Name, sans),
	}
}
