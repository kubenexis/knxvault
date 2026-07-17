package acme_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubenexis/knxvault/internal/acme"
)

func TestLoadProfileYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.yaml")
	content := `
profile: test
directory_url: https://acme-staging-v02.api.letsencrypt.org/directory
email: ops@example.com
accept_tos: true
account_key_file: ` + filepath.Join(dir, "account.key") + `
http01:
  mode: webroot
  webroot: ` + dir + `
domains:
  - name: app.example.com
    sans: [www.example.com]
delivery:
  type: files
  cert_path: ` + filepath.Join(dir, "fullchain.pem") + `
  key_path: ` + filepath.Join(dir, "key.pem") + `
renew_before: 720h
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := acme.LoadProfileYAML(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Email != "ops@example.com" || len(p.Domains) != 1 {
		t.Fatalf("%+v", p)
	}
	ord := p.PrimaryOrder()
	if ord.CommonName != "app.example.com" {
		t.Fatalf("%+v", ord)
	}
	http01, dns01, mem, err := acme.BuildSolversFromProfile(p)
	if err != nil || http01 == nil || dns01 != nil || mem != nil {
		t.Fatalf("solvers http=%v dns=%v mem=%v err=%v", http01, dns01, mem, err)
	}
}

func TestProfileRejectsSkipTLSForLE(t *testing.T) {
	p := &acme.Profile{
		DirectoryURL:  acme.StagingDirectory,
		Email:         "a@b.c",
		AcceptTOS:     true,
		SkipTLSVerify: true,
		HTTP01:        &acme.ProfileHTTP01{Mode: "webroot", Webroot: t.TempDir()},
		Domains:       []acme.ProfileDomain{{Name: "x.example"}},
		Delivery:      acme.ProfileDelivery{Type: "files", CertPath: "/c", KeyPath: "/k"},
	}
	// Staging is still public LE host.
	if err := p.Validate(); err == nil {
		t.Fatal("expected skip_tls_verify rejected for LE staging")
	}
}

func TestProfileRequiresTOS(t *testing.T) {
	p := &acme.Profile{
		DirectoryURL: acme.StagingDirectory,
		Email:        "a@b.c",
		HTTP01:       &acme.ProfileHTTP01{Mode: "webroot", Webroot: "/tmp"},
		Domains:      []acme.ProfileDomain{{Name: "x.example"}},
		Delivery:     acme.ProfileDelivery{CertPath: "/c", KeyPath: "/k"},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected accept_tos required")
	}
}

func TestWebrootHTTP01(t *testing.T) {
	root := t.TempDir()
	w := &acme.WebrootHTTP01{Root: root}
	if err := w.Present(t.Context(), "ex.com", "tok123", "keyauth"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".well-known", "acme-challenge", "tok123")
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "keyauth" {
		t.Fatalf("%s %v", b, err)
	}
	if err := w.CleanUp(t.Context(), "ex.com", "tok123", "keyauth"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expected removed")
	}
}

func TestListenHTTP01(t *testing.T) {
	m := acme.NewMemoryHTTP01()
	srv, ln, err := acme.ListenHTTP01("127.0.0.1:0", m)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	_ = ln.Close()
}
