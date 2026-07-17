// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package x509native

import (
	"crypto"
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

const organization = "KNXVault"

// MinRSAKeyBits is the minimum allowed RSA modulus size (W81-08).
const MinRSAKeyBits = 2048

func normalizeKeyBits(keyBits int) (int, error) {
	if keyBits == 0 {
		return MinRSAKeyBits, nil
	}
	if keyBits < MinRSAKeyBits {
		return 0, fmt.Errorf("rsa key_bits must be >= %d (got %d)", MinRSAKeyBits, keyBits)
	}
	return keyBits, nil
}

// CreateRoot generates a self-signed RSA SHA-256 root CA.
func CreateRoot(commonName string, ttl time.Duration, keyBits int) (certPEM, keyPEM []byte, err error) {
	keyBits, err = normalizeKeyBits(keyBits)
	if err != nil {
		return nil, nil, err
	}
	priv, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate root key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
		},
		NotBefore:             now,
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	return signCertificate(template, template, &priv.PublicKey, priv, priv)
}

// CreateIntermediate signs an intermediate CA certificate with the parent CA.
func CreateIntermediate(parentCertPEM, parentKeyPEM []byte, commonName string, ttl time.Duration, keyBits int) (certPEM, keyPEM []byte, err error) {
	parentCert, err := ParseCertificate(parentCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse parent certificate: %w", err)
	}
	parentKey, err := parsePrivateKey(parentKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse parent key: %w", err)
	}

	keyBits, err = normalizeKeyBits(keyBits)
	if err != nil {
		return nil, nil, err
	}
	priv, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate intermediate key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
		},
		NotBefore:             now,
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// W81-01: MaxPathLen 0 alone is ignored by Go unless MaxPathLenZero is true.
		MaxPathLen:         0,
		MaxPathLenZero:     true,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	return signCertificate(template, parentCert, &priv.PublicKey, parentKey, priv)
}

// IssueCertificate signs a leaf certificate with DNS SAN support (server EKU default).
func IssueCertificate(caCertPEM, caKeyPEM []byte, commonName string, dnsNames, ipAddresses []string, ttl time.Duration, keyBits int) (certPEM, keyPEM []byte, err error) {
	return IssueCertificateWithUsage(caCertPEM, caKeyPEM, commonName, dnsNames, ipAddresses, ttl, keyBits, "server")
}

// IssueCertificateWithUsage issues a leaf with role key usage (server|client|code_signing).
func IssueCertificateWithUsage(caCertPEM, caKeyPEM []byte, commonName string, dnsNames, ipAddresses []string, ttl time.Duration, keyBits int, usage string) (certPEM, keyPEM []byte, err error) {
	caCert, err := ParseCertificate(caCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca certificate: %w", err)
	}
	caKey, err := parsePrivateKey(caKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca key: %w", err)
	}

	keyBits, err = normalizeKeyBits(keyBits)
	if err != nil {
		return nil, nil, err
	}
	priv, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	ku, eku := keyUsageForRole(usage)
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
		},
		NotBefore:          now,
		NotAfter:           now.Add(ttl),
		KeyUsage:           ku,
		ExtKeyUsage:        eku,
		DNSNames:           append([]string(nil), dnsNames...),
		IPAddresses:        parseIPAddresses(ipAddresses),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	return signCertificate(template, caCert, &priv.PublicKey, caKey, priv)
}

// SignCSR signs an existing PEM CSR with the given CA certificate and key.
func SignCSR(csrPEM, caCertPEM, caKeyPEM []byte, ttl time.Duration) (certPEM []byte, err error) {
	return SignCSRWithUsage(csrPEM, caCertPEM, caKeyPEM, ttl, "server")
}

// SignCSRWithUsage signs a CSR applying role key usage (W78).
func SignCSRWithUsage(csrPEM, caCertPEM, caKeyPEM []byte, ttl time.Duration, usage string) (certPEM []byte, err error) {
	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil {
		return nil, fmt.Errorf("decode csr pem")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid csr signature: %w", err)
	}

	caCert, err := ParseCertificate(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ca certificate: %w", err)
	}
	caKey, err := parsePrivateKey(caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	ku, eku := keyUsageForRole(usage)
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             now,
		NotAfter:              now.Add(ttl),
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign csr: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func keyUsageForRole(usage string) (x509.KeyUsage, []x509.ExtKeyUsage) {
	switch strings.ToLower(strings.TrimSpace(usage)) {
	case "client":
		return x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "code_signing":
		return x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	default: // server (and empty)
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
}

func signCertificate(template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer, keyOut *rsa.PrivateKey) (certPEM, keyPEM []byte, err error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER := x509.MarshalPKCS1PrivateKey(keyOut)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("decode private key pem")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("pkcs8 key is not rsa")
		}
		return rsaKey, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func parseIPAddresses(raw []string) []net.IP {
	if len(raw) == 0 {
		return nil
	}
	out := make([]net.IP, 0, len(raw))
	for _, addr := range raw {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if ip := net.ParseIP(addr); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}
