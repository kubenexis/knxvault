// Package pki implements the PKI engine (LLD §4.A).
package pki

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"

	kvncrypto "github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/crypto/openssl"
	"github.com/kubenexis/knxvault/internal/domain/common"
	domainpki "github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/utils"
)

// CreateRootRequest configures a new root CA.
type CreateRootRequest struct {
	Name       string
	CommonName string
	TTL        string
	KeyBits    int
}

// CreateIntermediateRequest configures a new intermediate CA.
type CreateIntermediateRequest struct {
	ParentName string
	Name       string
	CommonName string
	TTL        string
	KeyBits    int
}

// IssueRequest configures leaf certificate issuance.
type IssueRequest struct {
	Role        string
	CommonName  string
	DNSNames    []string
	IPAddresses []string
	TTL         string
	KeyBits     int
}

// CAResult is returned when creating a CA.
type CAResult struct {
	ID        uuid.UUID
	Name      string
	CertPEM   string
	Serial    string
	ExpiresAt time.Time
}

// IssueResult is returned when issuing a leaf certificate.
type IssueResult struct {
	CertPEM       string
	PrivateKeyPEM string
	Serial        string
	ExpiresAt     time.Time
}

// Engine performs PKI operations via OpenSSL.
type Engine struct {
	openssl *openssl.Wrapper
	crypto  *kvncrypto.Service
	caRepo  repository.CARepository
	revoked repository.RevocationRepository
}

// NewEngine constructs a PKI engine.
func NewEngine(
	ossl *openssl.Wrapper,
	cryptoSvc *kvncrypto.Service,
	caRepo repository.CARepository,
	revoked repository.RevocationRepository,
) *Engine {
	return &Engine{
		openssl: ossl,
		crypto:  cryptoSvc,
		caRepo:  caRepo,
		revoked: revoked,
	}
}

// CreateRoot creates and stores a self-signed root CA.
func (e *Engine) CreateRoot(ctx context.Context, req CreateRootRequest) (*CAResult, error) {
	if e.crypto == nil || e.caRepo == nil {
		return nil, common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}

	ttl, err := utils.ParseTTL(req.TTL)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeValidation, "invalid ttl", err)
	}
	keyBits := req.KeyBits
	if keyBits == 0 {
		keyBits = 2048
	}

	ws, err := newWorkspace()
	if err != nil {
		return nil, err
	}
	defer ws.cleanup()

	subject := subjectDN(req.CommonName)
	days := int(ttl.Hours() / 24)
	if days < 1 {
		days = 1
	}

	if _, err := e.openssl.SafeExec(ctx, []string{
		"genrsa", "-out", ws.path("ca.key"), fmt.Sprintf("%d", keyBits),
	}, nil); err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "generate root key", err)
	}

	res, err := e.openssl.SafeExec(ctx, []string{
		"req", "-new", "-x509",
		"-key", ws.path("ca.key"),
		"-out", ws.path("ca.crt"),
		"-days", fmt.Sprintf("%d", days),
		"-subj", subject,
		"-sha256",
	}, nil)
	if err != nil || res.ExitCode != 0 {
		return nil, common.Wrap(common.ErrCodeInternal, "create root certificate", fmt.Errorf("%s", res.Stderr))
	}

	certPEM, err := ws.read("ca.crt")
	if err != nil {
		return nil, err
	}
	keyPEM, err := ws.read("ca.key")
	if err != nil {
		return nil, err
	}

	serial, expiresAt, err := parseCertMetadata(certPEM)
	if err != nil {
		return nil, err
	}

	keyEnc, dekEnc, err := e.crypto.Seal(keyPEM)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "encrypt root key", err)
	}

	ca := &domainpki.CA{
		ID:            uuid.New(),
		Name:          req.Name,
		Type:          domainpki.CATypeRoot,
		Subject:       domainpki.DistinguishedName{CommonName: req.CommonName},
		Serial:        serial,
		CertPEM:       string(certPEM),
		PrivateKeyEnc: keyEnc,
		DEKEnc:        dekEnc,
		Status:        domainpki.CAStatusActive,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     expiresAt,
	}
	if err := e.caRepo.Save(ctx, ca); err != nil {
		return nil, err
	}

	return &CAResult{
		ID:        ca.ID,
		Name:      ca.Name,
		CertPEM:   ca.CertPEM,
		Serial:    ca.Serial,
		ExpiresAt: ca.ExpiresAt,
	}, nil
}

// CreateIntermediate creates and signs an intermediate CA.
func (e *Engine) CreateIntermediate(ctx context.Context, req CreateIntermediateRequest) (*CAResult, error) {
	if e.crypto == nil || e.caRepo == nil {
		return nil, common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}

	parent, err := e.caRepo.GetByName(ctx, req.ParentName)
	if err != nil {
		return nil, err
	}

	ttl, err := utils.ParseTTL(req.TTL)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeValidation, "invalid ttl", err)
	}
	keyBits := req.KeyBits
	if keyBits == 0 {
		keyBits = 2048
	}

	ws, err := newWorkspace()
	if err != nil {
		return nil, err
	}
	defer ws.cleanup()

	parentKey, err := e.decryptKey(parent.PrivateKeyEnc, parent.DEKEnc)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(parentKey)

	if err := ws.write("parent.crt", []byte(parent.CertPEM)); err != nil {
		return nil, err
	}
	if err := ws.write("parent.key", parentKey); err != nil {
		return nil, err
	}

	if _, err := e.openssl.SafeExec(ctx, []string{
		"genrsa", "-out", ws.path("int.key"), fmt.Sprintf("%d", keyBits),
	}, nil); err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "generate intermediate key", err)
	}

	subject := subjectDN(req.CommonName)
	if _, err := e.openssl.SafeExec(ctx, []string{
		"req", "-new",
		"-key", ws.path("int.key"),
		"-out", ws.path("int.csr"),
		"-subj", subject,
		"-sha256",
	}, nil); err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "create intermediate csr", err)
	}

	days := int(ttl.Hours() / 24)
	if days < 1 {
		days = 1
	}
	res, err := e.openssl.SafeExec(ctx, []string{
		"x509", "-req",
		"-in", ws.path("int.csr"),
		"-CA", ws.path("parent.crt"),
		"-CAkey", ws.path("parent.key"),
		"-CAcreateserial",
		"-out", ws.path("int.crt"),
		"-days", fmt.Sprintf("%d", days),
		"-sha256",
	}, nil)
	if err != nil || res.ExitCode != 0 {
		return nil, common.Wrap(common.ErrCodeInternal, "sign intermediate certificate", fmt.Errorf("%s", res.Stderr))
	}

	certPEM, err := ws.read("int.crt")
	if err != nil {
		return nil, err
	}
	keyPEM, err := ws.read("int.key")
	if err != nil {
		return nil, err
	}

	serial, expiresAt, err := parseCertMetadata(certPEM)
	if err != nil {
		return nil, err
	}

	keyEnc, dekEnc, err := e.crypto.Seal(keyPEM)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "encrypt intermediate key", err)
	}

	parentID := parent.ID
	ca := &domainpki.CA{
		ID:            uuid.New(),
		ParentID:      &parentID,
		Name:          req.Name,
		Type:          domainpki.CATypeIntermediate,
		Subject:       domainpki.DistinguishedName{CommonName: req.CommonName},
		Serial:        serial,
		CertPEM:       string(certPEM),
		PrivateKeyEnc: keyEnc,
		DEKEnc:        dekEnc,
		Status:        domainpki.CAStatusActive,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     expiresAt,
	}
	if err := e.caRepo.Save(ctx, ca); err != nil {
		return nil, err
	}

	return &CAResult{
		ID:        ca.ID,
		Name:      ca.Name,
		CertPEM:   ca.CertPEM,
		Serial:    ca.Serial,
		ExpiresAt: ca.ExpiresAt,
	}, nil
}

// IssueCertificate issues a leaf certificate signed by the named CA role.
func (e *Engine) IssueCertificate(ctx context.Context, req IssueRequest) (*IssueResult, error) {
	if e.crypto == nil || e.caRepo == nil {
		return nil, common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}

	ca, err := e.caRepo.GetByName(ctx, req.Role)
	if err != nil {
		return nil, err
	}

	ttl := 720 * time.Hour
	if req.TTL != "" {
		ttl, err = utils.ParseTTL(req.TTL)
		if err != nil {
			return nil, common.Wrap(common.ErrCodeValidation, "invalid ttl", err)
		}
	}
	keyBits := req.KeyBits
	if keyBits == 0 {
		keyBits = 2048
	}

	ws, err := newWorkspace()
	if err != nil {
		return nil, err
	}
	defer ws.cleanup()

	caKey, err := e.decryptKey(ca.PrivateKeyEnc, ca.DEKEnc)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(caKey)

	if err := ws.write("ca.crt", []byte(ca.CertPEM)); err != nil {
		return nil, err
	}
	if err := ws.write("ca.key", caKey); err != nil {
		return nil, err
	}

	if _, err := e.openssl.SafeExec(ctx, []string{
		"genrsa", "-out", ws.path("leaf.key"), fmt.Sprintf("%d", keyBits),
	}, nil); err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "generate leaf key", err)
	}

	subject := subjectDN(req.CommonName)
	if _, err := e.openssl.SafeExec(ctx, []string{
		"req", "-new",
		"-key", ws.path("leaf.key"),
		"-out", ws.path("leaf.csr"),
		"-subj", subject,
		"-sha256",
	}, nil); err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "create leaf csr", err)
	}

	days := int(ttl.Hours() / 24)
	if days < 1 {
		days = 1
	}
	args := []string{
		"x509", "-req",
		"-in", ws.path("leaf.csr"),
		"-CA", ws.path("ca.crt"),
		"-CAkey", ws.path("ca.key"),
		"-CAcreateserial",
		"-out", ws.path("leaf.crt"),
		"-days", fmt.Sprintf("%d", days),
	}
	if len(req.DNSNames) > 0 {
		ext := "[v3_ext]\nsubjectAltName=DNS:" + strings.Join(req.DNSNames, ",DNS:") + "\n"
		if err := ws.write("ext.cnf", []byte(ext)); err != nil {
			return nil, err
		}
		args = append(args, "-extfile", ws.path("ext.cnf"), "-extensions", "v3_ext")
	} else {
		args = append(args, "-sha256")
	}

	res, err := e.openssl.SafeExec(ctx, args, nil)
	if err != nil || res.ExitCode != 0 {
		return nil, common.Wrap(common.ErrCodeInternal, "sign leaf certificate", fmt.Errorf("%s", res.Stderr))
	}

	certPEM, err := ws.read("leaf.crt")
	if err != nil {
		return nil, err
	}
	keyPEM, err := ws.read("leaf.key")
	if err != nil {
		return nil, err
	}

	serial, expiresAt, err := parseCertMetadata(certPEM)
	if err != nil {
		return nil, err
	}

	if e.revoked != nil {
		revoked, err := e.revoked.IsRevoked(ctx, serial)
		if err != nil {
			return nil, err
		}
		if revoked {
			return nil, common.New(common.ErrCodeValidation, "certificate serial is revoked")
		}
	}

	return &IssueResult{
		CertPEM:       string(certPEM),
		PrivateKeyPEM: string(keyPEM),
		Serial:        serial,
		ExpiresAt:     expiresAt,
	}, nil
}

// GetCA returns a CA by ID.
func (e *Engine) GetCA(ctx context.Context, id uuid.UUID) (*domainpki.CA, error) {
	if e.caRepo == nil {
		return nil, common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}
	return e.caRepo.GetByID(ctx, id)
}

// Revoke marks a certificate serial as revoked.
func (e *Engine) Revoke(ctx context.Context, caID uuid.UUID, serial, reason string) error {
	if e.revoked == nil {
		return common.New(common.ErrCodeInternal, "revocation repository not configured")
	}
	if serial == "" {
		return common.New(common.ErrCodeValidation, "serial is required")
	}
	if reason == "" {
		reason = "unspecified"
	}
	return e.revoked.Revoke(ctx, &repository.RevokedCertificate{
		Serial:    serial,
		CAID:      caID,
		RevokedAt: time.Now().UTC(),
		Reason:    reason,
	})
}

// GenerateCRL returns a PEM CRL for a CA from revoked serials.
func (e *Engine) GenerateCRL(ctx context.Context, caID uuid.UUID) (string, error) {
	if e.caRepo == nil || e.revoked == nil {
		return "", common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}

	ca, err := e.caRepo.GetByID(ctx, caID)
	if err != nil {
		return "", err
	}
	revoked, err := e.revoked.ListByCA(ctx, caID)
	if err != nil {
		return "", err
	}

	parentCert, err := parseCertificate([]byte(ca.CertPEM))
	if err != nil {
		return "", err
	}

	caKey, err := e.decryptKey(ca.PrivateKeyEnc, ca.DEKEnc)
	if err != nil {
		return "", err
	}
	defer zeroBytes(caKey)

	signer, err := parseSigner(caKey)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	tmpl := &x509.RevocationList{
		RevokedCertificateEntries: make([]x509.RevocationListEntry, 0, len(revoked)),
		Number:                    big.NewInt(1),
		ThisUpdate:                now,
		NextUpdate:                now.Add(24 * time.Hour),
	}
	for _, entry := range revoked {
		serial, ok := new(big.Int).SetString(entry.Serial, 16)
		if !ok {
			return "", fmt.Errorf("invalid serial %q", entry.Serial)
		}
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: entry.RevokedAt,
		})
	}

	der, err := x509.CreateRevocationList(rand.Reader, tmpl, parentCert, signer)
	if err != nil {
		return "", common.Wrap(common.ErrCodeInternal, "create crl", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})), nil
}

func (e *Engine) decryptKey(keyEnc, dekEnc []byte) ([]byte, error) {
	plain, err := e.crypto.Open(keyEnc, dekEnc)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "decrypt private key", err)
	}
	return plain, nil
}

func subjectDN(commonName string) string {
	return "/CN=" + commonName + "/O=KNXVault"
}

func parseCertMetadata(certPEM []byte) (serial string, expiresAt time.Time, err error) {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return "", time.Time{}, err
	}
	return cert.SerialNumber.Text(16), cert.NotAfter, nil
}

func parseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("decode certificate pem")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseSigner(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("decode private key pem")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("pkcs8 key is not a signer")
		}
		return signer, nil
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsaKey, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
