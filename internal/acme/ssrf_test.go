package acme_test

import (
	"net"
	"testing"

	"github.com/kubenexis/knxvault/internal/acme"
)

func TestValidateOutboundURLRejectsPrivateAndMetadata(t *testing.T) {
	t.Parallel()
	cases := []string{
		"",
		"ftp://example.com/",
		"http://",
		"http://127.0.0.1/hook",
		"https://10.0.0.5/x",
		"http://192.168.1.1/",
		"http://[::1]/",
		"http://169.254.169.254/latest",
		"http://metadata.google.internal/",
		"http://foo.internal/path",
	}
	for _, raw := range cases {
		if err := acme.ValidateOutboundURL(raw); err == nil {
			t.Errorf("ValidateOutboundURL(%q) = nil, want error", raw)
		}
	}
}

func TestValidateOutboundURLAllowsPublicIP(t *testing.T) {
	t.Parallel()
	// 8.8.8.8 is public DNS; literal IP path skips LookupIP.
	if err := acme.ValidateOutboundURL("https://8.8.8.8/acme"); err != nil {
		t.Fatalf("public IP: %v", err)
	}
}

func TestPublicLEHost(t *testing.T) {
	t.Parallel()
	if !acme.PublicLEHost("https://acme-v02.api.letsencrypt.org/directory") {
		t.Fatal("expected LE host")
	}
	if !acme.PublicLEHost("https://letsencrypt.org/") {
		t.Fatal("expected apex LE")
	}
	if acme.PublicLEHost("https://evil-letsencrypt.org.attacker.example/") {
		t.Fatal("substring false positive")
	}
	if acme.PublicLEHost("://bad") {
		t.Fatal("invalid url")
	}
	if acme.PublicLEHost("https://example.com/") {
		t.Fatal("non-LE host")
	}
}

func TestIsBlockedIPExportedViaValidate(t *testing.T) {
	t.Parallel()
	// Unspecified
	if err := acme.ValidateOutboundURL("http://0.0.0.0/"); err == nil {
		t.Fatal("want block unspecified")
	}
	// Link-local multicast representation rarely used as host; loopback covered above.
	_ = net.IPv4(127, 0, 0, 1)
}
