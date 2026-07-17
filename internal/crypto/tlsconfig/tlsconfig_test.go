// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package tlsconfig_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto/tlsconfig"
)

func TestLoadServerTLSWithMTLS(t *testing.T) {
	dir := t.TempDir()
	caKey, caCert := generateCA(t)
	caFile := writePEM(t, dir, "ca.pem", "CERTIFICATE", caCert)

	serverKey, serverCert := generateCert(t, caKey, caCert, "server")
	certFile := writePEM(t, dir, "server.pem", "CERTIFICATE", serverCert)
	keyFile := writeKey(t, dir, "server.key", serverKey)

	cfg, err := tlsconfig.LoadServerTLS(tlsconfig.ServerConfig{
		CertFile:     certFile,
		KeyFile:      keyFile,
		MTLSRequired: true,
		CAFile:       caFile,
	})
	if err != nil {
		t.Fatalf("LoadServerTLS: %v", err)
	}
	if cfg == nil || cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("unexpected tls config: %+v", cfg)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
	}
}

func generateCA(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func generateCert(t *testing.T, caKey *rsa.PrivateKey, caDER []byte, cn string) (*rsa.PrivateKey, []byte) {
	t.Helper()
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func writePEM(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeKey(t *testing.T, dir, name string, key *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	return writePEM(t, dir, name, "RSA PRIVATE KEY", der)
}
