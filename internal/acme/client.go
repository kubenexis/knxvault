package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// Client is an ACME issuer backed by golang.org/x/crypto/acme.
type Client struct {
	cfg    Config
	http01 HTTP01Presenter
	dns01  DNS01Presenter
	// newACME is injectable for tests.
	newACME func(key crypto.Signer, directory string, hc *http.Client) ACMEAPI
}

// ACMEAPI is the subset of x/crypto/acme.Client used by Issue (for mocks).
type ACMEAPI interface {
	Register(ctx context.Context, a *xacme.Account, prompt func(tos string) bool) (*xacme.Account, error)
	AuthorizeOrder(ctx context.Context, id []xacme.AuthzID, opts ...xacme.OrderOption) (*xacme.Order, error)
	GetAuthorization(ctx context.Context, url string) (*xacme.Authorization, error)
	Accept(ctx context.Context, chal *xacme.Challenge) (*xacme.Challenge, error)
	WaitAuthorization(ctx context.Context, url string) (*xacme.Authorization, error)
	WaitOrder(ctx context.Context, url string) (*xacme.Order, error)
	CreateOrderCert(ctx context.Context, url string, csr []byte, bundle bool) (der [][]byte, certURL string, err error)
	HTTP01ChallengeResponse(token string) (string, error)
	DNS01ChallengeRecord(token string) (string, error)
}

type realACME struct{ c *xacme.Client }

func (r *realACME) Register(ctx context.Context, a *xacme.Account, prompt func(tos string) bool) (*xacme.Account, error) {
	return r.c.Register(ctx, a, prompt)
}
func (r *realACME) AuthorizeOrder(ctx context.Context, id []xacme.AuthzID, opts ...xacme.OrderOption) (*xacme.Order, error) {
	return r.c.AuthorizeOrder(ctx, id, opts...)
}
func (r *realACME) GetAuthorization(ctx context.Context, url string) (*xacme.Authorization, error) {
	return r.c.GetAuthorization(ctx, url)
}
func (r *realACME) Accept(ctx context.Context, chal *xacme.Challenge) (*xacme.Challenge, error) {
	return r.c.Accept(ctx, chal)
}
func (r *realACME) WaitAuthorization(ctx context.Context, url string) (*xacme.Authorization, error) {
	return r.c.WaitAuthorization(ctx, url)
}
func (r *realACME) WaitOrder(ctx context.Context, url string) (*xacme.Order, error) {
	return r.c.WaitOrder(ctx, url)
}
func (r *realACME) CreateOrderCert(ctx context.Context, url string, csr []byte, bundle bool) ([][]byte, string, error) {
	return r.c.CreateOrderCert(ctx, url, csr, bundle)
}
func (r *realACME) HTTP01ChallengeResponse(token string) (string, error) {
	return r.c.HTTP01ChallengeResponse(token)
}
func (r *realACME) DNS01ChallengeRecord(token string) (string, error) {
	return r.c.DNS01ChallengeRecord(token)
}

// SetHTTP01Presenter replaces the HTTP-01 presenter (operator shared solver).
func SetHTTP01Presenter(c *Client, p HTTP01Presenter) {
	if c != nil {
		c.http01 = p
	}
}

// NewClient constructs an ACME client with optional solvers.
func NewClient(cfg Config, http01 HTTP01Presenter, dns01 DNS01Presenter) *Client {
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = xacme.LetsEncryptURL
	}
	return &Client{
		cfg:    cfg,
		http01: http01,
		dns01:  dns01,
		newACME: func(key crypto.Signer, directory string, hc *http.Client) ACMEAPI {
			return &realACME{c: &xacme.Client{Key: key, DirectoryURL: directory, HTTPClient: hc}}
		},
	}
}

// ProbeDirectory checks that the ACME directory is reachable.
func (c *Client) ProbeDirectory(ctx context.Context) CAInfo {
	info := CAInfo{DirectoryURL: c.cfg.DirectoryURL}
	if strings.TrimSpace(c.cfg.DirectoryURL) == "" {
		info.Message = "directory URL empty"
		return info
	}
	client := c.httpClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.DirectoryURL, nil)
	if err != nil {
		info.Message = err.Error()
		return info
	}
	resp, err := client.Do(req)
	if err != nil {
		info.Message = err.Error()
		return info
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		info.Ready = true
		info.Message = "directory reachable"
		return info
	}
	info.Message = fmt.Sprintf("directory status %d", resp.StatusCode)
	return info
}

// Issue obtains a certificate via ACME.
func (c *Client) Issue(ctx context.Context, req OrderRequest) (*Result, error) {
	if !c.cfg.AcceptTOS {
		return nil, fmt.Errorf("acme acceptTOS is required")
	}
	if c.cfg.SkipTLSVerify && PublicLEHost(c.cfg.DirectoryURL) {
		return nil, fmt.Errorf("skipTLSVerify is not allowed for public Let's Encrypt directories")
	}
	// SSRF: block private IP literals and metadata hosts on directory URL.
	// Lab SkipTLSVerify (Pebble on loopback) is allowed to use private hosts.
	if !c.cfg.SkipTLSVerify {
		if err := ValidateDirectoryURL(c.cfg.DirectoryURL); err != nil {
			return nil, fmt.Errorf("acme directory url: %w", err)
		}
	}
	names := uniqueNames(req.CommonName, req.DNSNames)
	if len(names) == 0 {
		return nil, fmt.Errorf("at least one domain required")
	}
	accountKey := c.cfg.AccountKey
	if accountKey == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		accountKey = k
	}
	api := c.newACME(accountKey, c.cfg.DirectoryURL, c.httpClient())

	acct := &xacme.Account{Contact: contactURIs(c.cfg.Email)}
	prompt := func(string) bool { return c.cfg.AcceptTOS }
	if _, err := api.Register(ctx, acct, prompt); err != nil {
		if !isAlreadyReg(err) {
			return nil, fmt.Errorf("acme register: %w", err)
		}
	}

	ids := xacme.DomainIDs(names...)
	order, err := api.AuthorizeOrder(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("acme authorize order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := api.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, err
		}
		if authz.Status == xacme.StatusValid {
			continue
		}
		chal, err := c.pickChallenge(authz)
		if err != nil {
			return nil, err
		}
		if err := c.solve(ctx, api, authz, chal); err != nil {
			return nil, err
		}
		// Always attempt cleanup after present (success or accept failure).
		defer c.cleanupChallenge(ctx, api, authz, chal)
		if _, err := api.Accept(ctx, chal); err != nil {
			return nil, fmt.Errorf("acme accept: %w", err)
		}
		if _, err := api.WaitAuthorization(ctx, authzURL); err != nil {
			return nil, fmt.Errorf("acme wait authz: %w", err)
		}
	}

	order, err = api.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("acme wait order: %w", err)
	}

	bits := req.KeyBits
	if bits < 2048 {
		bits = 2048
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: names[0]},
		DNSNames: names,
	}, leafKey)
	if err != nil {
		return nil, err
	}
	ders, _, err := api.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, fmt.Errorf("acme create cert: %w", err)
	}
	if len(ders) == 0 {
		return nil, fmt.Errorf("acme returned empty certificate")
	}
	return bundleResult(ders, leafKey)
}

func (c *Client) pickChallenge(authz *xacme.Authorization) (*xacme.Challenge, error) {
	prefer := c.cfg.Challenges
	if len(prefer) == 0 {
		prefer = []ChallengeType{ChallengeHTTP01, ChallengeDNS01}
	}
	for _, want := range prefer {
		for _, ch := range authz.Challenges {
			if ch.Status == xacme.StatusInvalid {
				continue
			}
			switch want {
			case ChallengeHTTP01:
				if ch.Type == "http-01" && c.http01 != nil {
					return ch, nil
				}
			case ChallengeDNS01:
				if ch.Type == "dns-01" && c.dns01 != nil {
					return ch, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no supported ACME challenge for %v (http01=%v dns01=%v)", authz.Identifier.Value, c.http01 != nil, c.dns01 != nil)
}

func (c *Client) solve(ctx context.Context, api ACMEAPI, authz *xacme.Authorization, chal *xacme.Challenge) error {
	domain := authz.Identifier.Value
	switch chal.Type {
	case "http-01":
		if c.http01 == nil {
			return fmt.Errorf("http-01 solver not configured")
		}
		keyAuth, err := api.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		if err := c.http01.Present(ctx, domain, chal.Token, keyAuth); err != nil {
			return err
		}
		// Best-effort cleanup after challenge is no longer needed is done by caller defer in Issue.
		return nil
	case "dns-01":
		if c.dns01 == nil {
			return fmt.Errorf("dns-01 solver not configured")
		}
		val, err := api.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return err
		}
		fqdn := DNS01FQDN(domain)
		return c.dns01.Present(ctx, domain, fqdn, val)
	default:
		return fmt.Errorf("unsupported challenge type %s", chal.Type)
	}
}

// cleanupChallenge removes presented challenge material (W50-13).
func (c *Client) cleanupChallenge(ctx context.Context, api ACMEAPI, authz *xacme.Authorization, chal *xacme.Challenge) {
	if authz == nil || chal == nil {
		return
	}
	domain := authz.Identifier.Value
	switch chal.Type {
	case "http-01":
		if c.http01 == nil {
			return
		}
		keyAuth, err := api.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return
		}
		_ = c.http01.CleanUp(ctx, domain, chal.Token, keyAuth)
	case "dns-01":
		if c.dns01 == nil {
			return
		}
		val, err := api.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return
		}
		_ = c.dns01.CleanUp(ctx, domain, DNS01FQDN(domain), val)
	}
}

func (c *Client) httpClient() *http.Client {
	// Safe clone: DefaultTransport may be replaced in tests/custom agents.
	var tr http.RoundTripper = http.DefaultTransport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		cloned := base.Clone()
		if c.cfg.SkipTLSVerify {
			// Lab/staging ACME only — gated by explicit SkipTLSVerify config.
			cloned.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402
		}
		tr = cloned
	} else if c.cfg.SkipTLSVerify {
		// Fallback transport when DefaultTransport is not *http.Transport.
		tr = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: tr}
}

func contactURIs(email string) []string {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil
	}
	if strings.HasPrefix(email, "mailto:") {
		return []string{email}
	}
	return []string{"mailto:" + email}
}

func isAlreadyReg(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "already") || strings.Contains(s, "conflict")
}

func bundleResult(ders [][]byte, key *rsa.PrivateKey) (*Result, error) {
	var chain strings.Builder
	for _, der := range ders {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	issuer := ""
	if len(ders) > 1 {
		issuer = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ders[1]}))
	}
	return &Result{
		CertPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ders[0]})),
		PrivateKeyPEM: string(keyPEM),
		IssuerPEM:     issuer,
		ChainPEM:      chain.String(),
		Serial:        formatSerial(leaf.SerialNumber),
		NotBefore:     leaf.NotBefore.UTC(),
		NotAfter:      leaf.NotAfter.UTC(),
	}, nil
}
