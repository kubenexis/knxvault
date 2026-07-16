package acme

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// SelfSignedIssuer issues self-signed leaf certificates (no ACME, no vault).
// Useful for lab, development, and multi-issuer coverage without external CA.
type SelfSignedIssuer struct {
	// NotAfter overrides default lifetime when non-zero.
	DefaultTTL time.Duration
}

// Issue creates a self-signed certificate for the requested names.
func (s *SelfSignedIssuer) Issue(_ context.Context, req OrderRequest) (*Result, error) {
	cn := strings.TrimSpace(req.CommonName)
	if cn == "" && len(req.DNSNames) > 0 {
		cn = req.DNSNames[0]
	}
	if cn == "" {
		return nil, fmt.Errorf("common_name or dnsNames required")
	}
	bits := req.KeyBits
	if bits < 2048 {
		bits = 2048
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = s.DefaultTTL
	}
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     uniqueNames(cn, req.DNSNames),
		IPAddresses:  parseIPs(req.IPAddresses),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return &Result{
		CertPEM:       string(certPEM),
		PrivateKeyPEM: string(keyPEM),
		IssuerPEM:     string(certPEM),
		ChainPEM:      string(certPEM),
		Serial:        formatSerial(serial),
		NotBefore:     tmpl.NotBefore,
		NotAfter:      tmpl.NotAfter,
	}, nil
}

func uniqueNames(cn string, dns []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	add(cn)
	for _, d := range dns {
		add(d)
	}
	return out
}

func parseIPs(addrs []string) []net.IP {
	var out []net.IP
	for _, a := range addrs {
		if ip := net.ParseIP(strings.TrimSpace(a)); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func formatSerial(n *big.Int) string {
	b := n.Bytes()
	if len(b) == 0 {
		return "00"
	}
	var parts []string
	for _, x := range b {
		parts = append(parts, fmt.Sprintf("%02x", x))
	}
	return strings.Join(parts, ":")
}
