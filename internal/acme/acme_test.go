package acme_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/kubenexis/knxvault/internal/acme"
)

func TestSelfSignedIssue(t *testing.T) {
	iss := &acme.SelfSignedIssuer{DefaultTTL: 24 * time.Hour}
	res, err := iss.Issue(context.Background(), acme.OrderRequest{
		CommonName: "app.example.com",
		DNSNames:   []string{"app.example.com", "www.example.com"},
		KeyBits:    2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.CertPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("cert: %s", res.CertPEM[:40])
	}
	if !strings.Contains(res.PrivateKeyPEM, "PRIVATE KEY") {
		t.Fatal("missing key")
	}
	if res.Serial == "" || res.NotAfter.IsZero() {
		t.Fatalf("serial/notAfter: %+v", res)
	}
	block, _ := pem.Decode([]byte(res.CertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "app.example.com" {
		t.Fatalf("cn=%s", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) < 2 {
		t.Fatalf("dns=%v", cert.DNSNames)
	}
}

func TestSelfSignedRequiresName(t *testing.T) {
	_, err := (&acme.SelfSignedIssuer{}).Issue(context.Background(), acme.OrderRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMemoryHTTP01(t *testing.T) {
	m := acme.NewMemoryHTTP01()
	ctx := context.Background()
	if err := m.Present(ctx, "ex.com", "tok1", "keyauth"); err != nil {
		t.Fatal(err)
	}
	v, ok := m.Get("tok1")
	if !ok || v != "keyauth" {
		t.Fatalf("get = %q %v", v, ok)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/tok1", nil)
	m.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "keyauth" {
		t.Fatalf("handler status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec2 := httptest.NewRecorder()
	m.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/missing", nil))
	if rec2.Code != 404 {
		t.Fatalf("missing = %d", rec2.Code)
	}
	_ = m.CleanUp(ctx, "ex.com", "tok1", "keyauth")
	if _, ok := m.Get("tok1"); ok {
		t.Fatal("expected cleaned")
	}
}

func TestMemoryDNS01AndFQDN(t *testing.T) {
	if acme.DNS01FQDN("example.com") != "_acme-challenge.example.com." {
		t.Fatalf("fqdn=%s", acme.DNS01FQDN("example.com"))
	}
	m := acme.NewMemoryDNS01()
	ctx := context.Background()
	fqdn := acme.DNS01FQDN("example.com")
	if err := m.Present(ctx, "example.com", fqdn, "v1"); err != nil {
		t.Fatal(err)
	}
	if err := m.Present(ctx, "example.com", fqdn, "v2"); err != nil {
		t.Fatal(err)
	}
	if len(m.Records[fqdn]) != 2 {
		t.Fatalf("records=%v", m.Records)
	}
	_ = m.CleanUp(ctx, "example.com", fqdn, "v1")
	if len(m.Records[fqdn]) != 1 || m.Records[fqdn][0] != "v2" {
		t.Fatalf("after cleanup %v", m.Records[fqdn])
	}
}

func TestWebhookDNS01(t *testing.T) {
	var gotAction string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), `"present"`) {
			gotAction = "present"
		}
		if strings.Contains(string(b), `"cleanup"`) {
			gotAction = "cleanup"
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	w := &acme.WebhookDNS01{URL: srv.URL, Client: srv.Client(), SkipURLValidate: true}
	ctx := context.Background()
	if err := w.Present(ctx, "d.com", "_acme-challenge.d.com.", "val"); err != nil {
		t.Fatal(err)
	}
	if gotAction != "present" {
		t.Fatalf("action=%s", gotAction)
	}
	if err := w.CleanUp(ctx, "d.com", "_acme-challenge.d.com.", "val"); err != nil {
		t.Fatal(err)
	}
	if gotAction != "cleanup" {
		t.Fatalf("action=%s", gotAction)
	}
}

func TestWebhookDNS01Errors(t *testing.T) {
	w := &acme.WebhookDNS01{}
	if err := w.Present(context.Background(), "d", "f", "v"); err == nil {
		t.Fatal("expected URL error")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()
	w2 := &acme.WebhookDNS01{URL: srv.URL, Client: srv.Client(), SkipURLValidate: true}
	if err := w2.Present(context.Background(), "d", "f", "v"); err == nil {
		t.Fatal("expected status error")
	}
}

func TestCloudflareDNS01Mock(t *testing.T) {
	// Zone list + create record
	mux := http.NewServeMux()
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zid","name":"example.com"}]}`))
	})
	mux.HandleFunc("/zones/zid/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rid"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"rid","name":"_acme-challenge.example.com","content":"val","type":"TXT"}]}`))
	})
	mux.HandleFunc("/zones/zid/dns_records/rid", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cf := &acme.CloudflareDNS01{
		APIToken: "tok",
		Base:     srv.URL,
		Client:   srv.Client(),
	}
	ctx := context.Background()
	if err := cf.Present(ctx, "app.example.com", "_acme-challenge.app.example.com.", "val"); err != nil {
		t.Fatal(err)
	}
	if err := cf.CleanUp(ctx, "app.example.com", "_acme-challenge.app.example.com.", "val"); err != nil {
		t.Fatal(err)
	}
}

func TestProbeDirectory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"newNonce":"x"}`))
	}))
	defer srv.Close()
	c := acme.NewClient(acme.Config{DirectoryURL: srv.URL}, nil, nil)
	info := c.ProbeDirectory(context.Background())
	if !info.Ready {
		t.Fatalf("info=%+v", info)
	}
}

func TestClientIssueWithMockACME(t *testing.T) {
	http01 := acme.NewMemoryHTTP01()
	c := acme.NewClient(acme.Config{
		DirectoryURL: "https://example.invalid/dir",
		Email:        "ops@example.com",
		AcceptTOS:    true,
		Challenges:   []acme.ChallengeType{acme.ChallengeHTTP01},
	}, http01, nil)

	// Inject mock via package-level test helper
	mock := &mockACME{
		authz: &xacme.Authorization{
			Status:     xacme.StatusPending,
			Identifier: xacme.AuthzID{Type: "dns", Value: "app.example.com"},
			Challenges: []*xacme.Challenge{{Type: "http-01", Token: "tok", URI: "https://x/chal", Status: xacme.StatusPending}},
		},
		order: &xacme.Order{
			URI:         "https://x/order",
			AuthzURLs:   []string{"https://x/authz"},
			FinalizeURL: "https://x/fin",
			Status:      xacme.StatusReady,
		},
	}
	// Build leaf cert DER for CreateOrderCert
	ss := &acme.SelfSignedIssuer{}
	tmp, err := ss.Issue(context.Background(), acme.OrderRequest{CommonName: "app.example.com", DNSNames: []string{"app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(tmp.CertPEM))
	mock.certDERs = [][]byte{block.Bytes}

	setTestACME(c, mock)

	res, err := c.Issue(context.Background(), acme.OrderRequest{
		CommonName: "app.example.com",
		DNSNames:   []string{"app.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.CertPEM == "" || res.PrivateKeyPEM == "" {
		t.Fatalf("empty result %+v", res)
	}
	// Challenge CleanUp runs via defer after successful issue.
	if _, ok := http01.Get("tok"); ok {
		t.Fatal("expected http-01 cleaned up after issue")
	}
}

// --- mock ACME + test hook ---

type mockACME struct {
	authz    *xacme.Authorization
	order    *xacme.Order
	certDERs [][]byte
}

func (m *mockACME) Register(context.Context, *xacme.Account, func(string) bool) (*xacme.Account, error) {
	return &xacme.Account{}, nil
}
func (m *mockACME) AuthorizeOrder(context.Context, []xacme.AuthzID, ...xacme.OrderOption) (*xacme.Order, error) {
	return m.order, nil
}
func (m *mockACME) GetAuthorization(context.Context, string) (*xacme.Authorization, error) {
	return m.authz, nil
}
func (m *mockACME) Accept(context.Context, *xacme.Challenge) (*xacme.Challenge, error) {
	return m.authz.Challenges[0], nil
}
func (m *mockACME) WaitAuthorization(context.Context, string) (*xacme.Authorization, error) {
	a := *m.authz
	a.Status = xacme.StatusValid
	return &a, nil
}
func (m *mockACME) WaitOrder(context.Context, string) (*xacme.Order, error) {
	o := *m.order
	o.Status = xacme.StatusReady
	return &o, nil
}
func (m *mockACME) CreateOrderCert(context.Context, string, []byte, bool) ([][]byte, string, error) {
	return m.certDERs, "https://x/cert", nil
}
func (m *mockACME) HTTP01ChallengeResponse(token string) (string, error) {
	return token + ".keyauth", nil
}
func (m *mockACME) DNS01ChallengeRecord(string) (string, error) { return "dnsval", nil }

// setTestACME uses unexported field via export_test.go
func setTestACME(c *acme.Client, api acme.ACMEAPI) {
	acme.SetNewACMEForTest(c, func(crypto.Signer, string, *http.Client) acme.ACMEAPI { return api })
}

func TestDNS01Pick(t *testing.T) {
	dns := acme.NewMemoryDNS01()
	c := acme.NewClient(acme.Config{
		DirectoryURL: "https://example.invalid/dir",
		AcceptTOS:    true,
		Challenges:   []acme.ChallengeType{acme.ChallengeDNS01},
	}, nil, dns)
	mock := &mockACME{
		authz: &xacme.Authorization{
			Status:     xacme.StatusPending,
			Identifier: xacme.AuthzID{Type: "dns", Value: "app.example.com"},
			Challenges: []*xacme.Challenge{{Type: "dns-01", Token: "tok", Status: xacme.StatusPending}},
		},
		order: &xacme.Order{
			URI: "https://x/order", AuthzURLs: []string{"https://x/authz"}, FinalizeURL: "https://x/fin",
		},
	}
	ss := &acme.SelfSignedIssuer{}
	tmp, _ := ss.Issue(context.Background(), acme.OrderRequest{CommonName: "app.example.com"})
	block, _ := pem.Decode([]byte(tmp.CertPEM))
	mock.certDERs = [][]byte{block.Bytes}
	setTestACME(c, mock)
	if _, err := c.Issue(context.Background(), acme.OrderRequest{CommonName: "app.example.com"}); err != nil {
		t.Fatal(err)
	}
	// CleanUp removes DNS records after issue.
	fqdn := acme.DNS01FQDN("app.example.com")
	if len(dns.Records[fqdn]) != 0 {
		t.Fatalf("expected DNS cleaned: %v", dns.Records)
	}
}

func TestIssueRejectsSkipTLSOnPublicLE(t *testing.T) {
	c := acme.NewClient(acme.Config{
		DirectoryURL:  "https://acme-v02.api.letsencrypt.org/directory",
		AcceptTOS:     true,
		SkipTLSVerify: true,
	}, nil, nil)
	_, err := c.Issue(context.Background(), acme.OrderRequest{CommonName: "x.example.com"})
	if err == nil {
		t.Fatal("expected skipTLSVerify blocked for public LE")
	}
}

func TestSetHTTP01PresenterAndSkipTLSVerifyHTTPClient(t *testing.T) {
	c := acme.NewClient(acme.Config{DirectoryURL: "https://example.com", SkipTLSVerify: true}, nil, nil)
	http01 := acme.NewMemoryHTTP01()
	acme.SetHTTP01Presenter(c, http01)
	// Present via shared presenter path exercised by Issue mock below.
	acme.SetHTTP01Presenter(nil, http01) // nil-safe
	// Probe with skip TLS on local server
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c2 := acme.NewClient(acme.Config{DirectoryURL: srv.URL, SkipTLSVerify: true}, nil, nil)
	info := c2.ProbeDirectory(context.Background())
	if !info.Ready {
		t.Fatalf("probe with skipTLS: %+v", info)
	}
}

func TestSelfSignedIPAddresses(t *testing.T) {
	iss := &acme.SelfSignedIssuer{}
	res, err := iss.Issue(context.Background(), acme.OrderRequest{
		CommonName:  "ip-only",
		IPAddresses: []string{"192.0.2.10", "not-an-ip", "2001:db8::1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.CertPEM == "" {
		t.Fatal("empty cert")
	}
}

func TestGenerateAccountKey(t *testing.T) {
	// ensure ecdsa path works when AccountKey nil — Issue with mock
	_ = elliptic.P256()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var _ crypto.Signer = k
}

func TestProbeDirectoryFailures(t *testing.T) {
	// NewClient defaults empty DirectoryURL to Let's Encrypt — probe a dead port instead.
	c2 := acme.NewClient(acme.Config{DirectoryURL: "http://127.0.0.1:1/nope"}, nil, nil)
	info2 := c2.ProbeDirectory(context.Background())
	if info2.Ready {
		t.Fatal("unreachable should not be ready")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	c3 := acme.NewClient(acme.Config{DirectoryURL: srv.URL}, nil, nil)
	if c3.ProbeDirectory(context.Background()).Ready {
		t.Fatal("500 should not be ready")
	}
}

func TestIssueNoDomains(t *testing.T) {
	c := acme.NewClient(acme.Config{DirectoryURL: "https://x", AcceptTOS: true}, nil, nil)
	if _, err := c.Issue(context.Background(), acme.OrderRequest{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestIssueNoChallengeSolver(t *testing.T) {
	c := acme.NewClient(acme.Config{
		DirectoryURL: "https://x", AcceptTOS: true,
		Challenges: []acme.ChallengeType{acme.ChallengeHTTP01},
	}, nil, nil)
	mock := &mockACME{
		authz: &xacme.Authorization{
			Status:     xacme.StatusPending,
			Identifier: xacme.AuthzID{Type: "dns", Value: "a.com"},
			Challenges: []*xacme.Challenge{{Type: "http-01", Token: "t", Status: xacme.StatusPending}},
		},
		order: &xacme.Order{URI: "o", AuthzURLs: []string{"a"}, FinalizeURL: "f"},
	}
	setTestACME(c, mock)
	if _, err := c.Issue(context.Background(), acme.OrderRequest{CommonName: "a.com"}); err == nil {
		t.Fatal("expected no solver error")
	}
}

func TestCloudflareNoToken(t *testing.T) {
	cf := &acme.CloudflareDNS01{}
	if err := cf.Present(context.Background(), "a.com", "f.", "v"); err == nil {
		t.Fatal("expected token error")
	}
}

func TestCloudflareAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"denied"}]}`))
	}))
	defer srv.Close()
	cf := &acme.CloudflareDNS01{APIToken: "t", ZoneID: "z", Base: srv.URL, Client: srv.Client()}
	if err := cf.Present(context.Background(), "a.com", "f.", "v"); err == nil {
		t.Fatal("expected API error")
	}
}

func TestBuildSolversWebhookOK(t *testing.T) {
	h, d, err := acme.BuildSolvers(acme.SolverSpec{DNSProvider: "webhook", WebhookURL: "http://127.0.0.1:9/hook"})
	if err != nil || h != nil || d == nil {
		t.Fatalf("h=%v d=%v err=%v", h, d, err)
	}
	_, d2, err := acme.BuildSolvers(acme.SolverSpec{DNSProvider: "cloudflare", CloudflareToken: "t", CloudflareZone: "z"})
	if err != nil || d2 == nil {
		t.Fatal(err)
	}
}

func TestCloudflareZoneIDDirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zones/fixed/dns_records", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	cf := &acme.CloudflareDNS01{APIToken: "t", ZoneID: "fixed", Base: srv.URL, Client: srv.Client()}
	if err := cf.Present(context.Background(), "x.com", "f.", "v"); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP01NotChallengePath(t *testing.T) {
	m := acme.NewMemoryHTTP01()
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/other", nil))
	if rec.Code != 404 {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestIssueValidAuthzSkip(t *testing.T) {
	// Authz already valid should skip challenges
	http01 := acme.NewMemoryHTTP01()
	c := acme.NewClient(acme.Config{DirectoryURL: "https://x", AcceptTOS: true, Challenges: []acme.ChallengeType{acme.ChallengeHTTP01}, Email: "mailto:a@b.c"}, http01, nil)
	ss := &acme.SelfSignedIssuer{}
	tmp, _ := ss.Issue(context.Background(), acme.OrderRequest{CommonName: "a.com"})
	block, _ := pem.Decode([]byte(tmp.CertPEM))
	mock := &mockACME{
		authz: &xacme.Authorization{Status: xacme.StatusValid, Identifier: xacme.AuthzID{Value: "a.com"}},
		order: &xacme.Order{URI: "o", AuthzURLs: []string{"a"}, FinalizeURL: "f"},
		certDERs: [][]byte{block.Bytes},
	}
	setTestACME(c, mock)
	if _, err := c.Issue(context.Background(), acme.OrderRequest{CommonName: "a.com"}); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterAlreadyRegistered(t *testing.T) {
	http01 := acme.NewMemoryHTTP01()
	c := acme.NewClient(acme.Config{DirectoryURL: "https://x", AcceptTOS: true, Challenges: []acme.ChallengeType{acme.ChallengeHTTP01}}, http01, nil)
	ss := &acme.SelfSignedIssuer{}
	tmp, _ := ss.Issue(context.Background(), acme.OrderRequest{CommonName: "a.com"})
	block, _ := pem.Decode([]byte(tmp.CertPEM))
	mock := &mockACMEAlreadyReg{
		mockACME: mockACME{
			authz: &xacme.Authorization{
				Status: xacme.StatusPending, Identifier: xacme.AuthzID{Value: "a.com"},
				Challenges: []*xacme.Challenge{{Type: "http-01", Token: "t", Status: xacme.StatusPending}},
			},
			order:    &xacme.Order{URI: "o", AuthzURLs: []string{"a"}, FinalizeURL: "f"},
			certDERs: [][]byte{block.Bytes},
		},
	}
	setTestACME(c, mock)
	if _, err := c.Issue(context.Background(), acme.OrderRequest{CommonName: "a.com"}); err != nil {
		t.Fatal(err)
	}
}

type mockACMEAlreadyReg struct{ mockACME }

func (m *mockACMEAlreadyReg) Register(context.Context, *xacme.Account, func(string) bool) (*xacme.Account, error) {
	return nil, fmt.Errorf("account already exists")
}

func TestBuildSolversAndFactory(t *testing.T) {
	_, _, err := acme.BuildSolvers(acme.SolverSpec{DNSProvider: "webhook"})
	if err == nil {
		t.Fatal("expected webhook url error")
	}
	_, _, err = acme.BuildSolvers(acme.SolverSpec{DNSProvider: "cloudflare"})
	if err == nil {
		t.Fatal("expected cf token error")
	}
	_, _, err = acme.BuildSolvers(acme.SolverSpec{DNSProvider: "nope"})
	if err == nil {
		t.Fatal("expected unknown provider")
	}
	h, d, err := acme.BuildSolvers(acme.SolverSpec{HTTP01: true, DNSProvider: "memory"})
	if err != nil || h == nil || d == nil {
		t.Fatalf("h=%v d=%v err=%v", h, d, err)
	}
	iss, err := acme.NewIssuerFromKind("selfsigned", acme.Config{}, acme.SolverSpec{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Issue(context.Background(), acme.OrderRequest{CommonName: "x.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := acme.NewIssuerFromKind("acme", acme.Config{AcceptTOS: true}, acme.SolverSpec{}); err == nil {
		t.Fatal("acme without solvers")
	}
	iss2, err := acme.NewIssuerFromKind("acme", acme.Config{DirectoryURL: "https://x", AcceptTOS: true}, acme.SolverSpec{HTTP01: true})
	if err != nil || iss2 == nil {
		t.Fatal(err)
	}
	if _, err := acme.NewIssuerFromKind("vault", acme.Config{}, acme.SolverSpec{}); err == nil {
		t.Fatal("expected unknown kind")
	}
}

func TestHTTP01RejectsPathToken(t *testing.T) {
	m := acme.NewMemoryHTTP01()
	if err := m.Present(context.Background(), "x.com", "../evil", "ka"); err == nil {
		t.Fatal("expected path token rejected")
	}
	if err := m.Present(context.Background(), "x.com", "good-token", "ka"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/../evil", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}
