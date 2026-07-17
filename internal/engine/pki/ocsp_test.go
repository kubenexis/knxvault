package pki_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"

	kvncrypto "github.com/kubenexis/knxvault/internal/crypto"
	domainpki "github.com/kubenexis/knxvault/internal/domain/pki"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func testMasterKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x42
	}
	return key
}

func TestHandleOCSPGoodAndRevoked(t *testing.T) {
	caRepo := memory.NewCARepository()
	revokeRepo := memory.NewRevocationRepository()
	cryptoSvc, err := kvncrypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	issuerCert, issuerKey, caPEM, keyPEM, caSerial := generateTestCA(t)
	keyEnc, dekEnc, err := cryptoSvc.Seal(keyPEM)
	if err != nil {
		t.Fatalf("Seal() = %v", err)
	}
	caID := uuid.New()
	ca := &domainpki.CA{
		ID:            caID,
		Name:          "test-ca",
		Type:          domainpki.CATypeRoot,
		Subject:       domainpki.DistinguishedName{CommonName: "Test CA"},
		Serial:        caSerial,
		CertPEM:       string(caPEM),
		PrivateKeyEnc: keyEnc,
		DEKEnc:        dekEnc,
		Status:        domainpki.CAStatusActive,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour),
	}
	if err := caRepo.Save(context.Background(), ca); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	engine := pkiengine.NewEngine(cryptoSvc, caRepo, revokeRepo)

	leafCert, err := generateLeafCert(issuerCert, issuerKey, big.NewInt(42))
	if err != nil {
		t.Fatalf("generateLeafCert() = %v", err)
	}
	reqDER, err := ocsp.CreateRequest(leafCert, issuerCert, nil)
	if err != nil {
		t.Fatalf("CreateRequest() = %v", err)
	}

	respDER, err := engine.HandleOCSP(context.Background(), caID, reqDER)
	if err != nil {
		t.Fatalf("HandleOCSP() = %v", err)
	}
	resp, err := ocsp.ParseResponse(respDER, issuerCert)
	if err != nil {
		t.Fatalf("ParseResponse() = %v", err)
	}
	if resp.Status != ocsp.Good {
		t.Fatalf("status = %d, want good", resp.Status)
	}

	leafSerial := leafCert.SerialNumber.Text(16)
	if err := revokeRepo.Revoke(context.Background(), &repository.RevokedCertificate{
		Serial:    leafSerial,
		CAID:      caID,
		RevokedAt: time.Now().UTC(),
		Reason:    "test",
	}); err != nil {
		t.Fatalf("Revoke() = %v", err)
	}

	respDER, err = engine.HandleOCSP(context.Background(), caID, reqDER)
	if err != nil {
		t.Fatalf("HandleOCSP() = %v", err)
	}
	resp, err = ocsp.ParseResponse(respDER, issuerCert)
	if err != nil {
		t.Fatalf("ParseResponse() = %v", err)
	}
	if resp.Status != ocsp.Revoked {
		t.Fatalf("status = %d, want revoked", resp.Status)
	}
}

func generateTestCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte, []byte, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() = %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() = %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return cert, key, certPEM, keyPEM, tmpl.SerialNumber.Text(16)
}

func generateLeafCert(issuer *x509.Certificate, issuerKey *rsa.PrivateKey, serial *big.Int) (*x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
