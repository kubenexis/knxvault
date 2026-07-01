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
	"time"

	"github.com/google/uuid"

	kvncrypto "github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/crypto/memzero"
	"github.com/kubenexis/knxvault/internal/crypto/openssl"
	pkibackend "github.com/kubenexis/knxvault/internal/crypto/pki"
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
	AutoRenew   bool
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

// Engine performs PKI operations via a pluggable backend.
type Engine struct {
	backend  pkibackend.Backend
	crypto   *kvncrypto.Service
	caRepo   repository.CARepository
	roleRepo repository.PKIRoleRepository
	revoked  repository.RevocationRepository
	issued   repository.IssuedCertRepository
}

// NewEngine constructs a PKI engine.
func NewEngine(
	ossl *openssl.Wrapper,
	cryptoSvc *kvncrypto.Service,
	caRepo repository.CARepository,
	revoked repository.RevocationRepository,
) *Engine {
	e := &Engine{
		crypto:  cryptoSvc,
		caRepo:  caRepo,
		revoked: revoked,
	}
	if ossl != nil {
		e.backend = pkibackend.NewOpenSSLBackend(ossl)
	}
	return e
}

// SetBackend configures the PKI issuance backend.
func (e *Engine) SetBackend(backend pkibackend.Backend) {
	e.backend = backend
}

// SetIssuedCertRepository configures issued certificate tracking for renewal.
func (e *Engine) SetIssuedCertRepository(repo repository.IssuedCertRepository) {
	e.issued = repo
}

// SetPKIRoleRepository configures persisted PKI issuance roles.
func (e *Engine) SetPKIRoleRepository(repo repository.PKIRoleRepository) {
	e.roleRepo = repo
}

// CreateRoot creates and stores a self-signed root CA.
func (e *Engine) CreateRoot(ctx context.Context, req CreateRootRequest) (*CAResult, error) {
	if e.crypto == nil || e.caRepo == nil || e.backend == nil {
		return nil, common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}

	ttl, err := utils.ParseTTL(req.TTL)
	if err != nil {
		return nil, common.Wrap(common.ErrCodeValidation, "invalid ttl", err)
	}

	certPEM, keyPEM, err := e.backend.CreateRoot(ctx, pkibackend.RootRequest{
		CommonName: req.CommonName,
		TTL:        ttl,
		KeyBits:    req.KeyBits,
	})
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "create root certificate", err)
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
	if e.crypto == nil || e.caRepo == nil || e.backend == nil {
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

	parentKey, err := e.decryptKey(parent.PrivateKeyEnc, parent.DEKEnc)
	if err != nil {
		return nil, err
	}
	defer memzero.Bytes(parentKey)

	certPEM, keyPEM, err := e.backend.CreateIntermediate(ctx, pkibackend.IntermediateRequest{
		ParentCertPEM: []byte(parent.CertPEM),
		ParentKeyPEM:  parentKey,
		CommonName:    req.CommonName,
		TTL:           ttl,
		KeyBits:       req.KeyBits,
	})
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "sign intermediate certificate", err)
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
	if e.crypto == nil || e.caRepo == nil || e.backend == nil {
		return nil, common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}

	caName := req.Role
	var pkiRole *domainpki.Role
	if e.roleRepo != nil {
		role, err := e.roleRepo.Get(ctx, req.Role)
		if err == nil {
			pkiRole = role
			caName = role.CAName
		}
	}

	ca, err := e.caRepo.GetByName(ctx, caName)
	if err != nil {
		return nil, err
	}

	if pkiRole != nil {
		if err := validateIssueAgainstRole(pkiRole, req); err != nil {
			return nil, err
		}
	}

	ttl := 720 * time.Hour
	if req.TTL != "" {
		ttl, err = utils.ParseTTL(req.TTL)
		if err != nil {
			return nil, common.Wrap(common.ErrCodeValidation, "invalid ttl", err)
		}
	}
	caKey, err := e.decryptKey(ca.PrivateKeyEnc, ca.DEKEnc)
	if err != nil {
		return nil, err
	}
	defer memzero.Bytes(caKey)

	certPEM, keyPEM, err := e.backend.IssueCertificate(ctx, pkibackend.IssueRequest{
		CACertPEM:   []byte(ca.CertPEM),
		CAKeyPEM:    caKey,
		CommonName:  req.CommonName,
		DNSNames:    req.DNSNames,
		IPAddresses: req.IPAddresses,
		TTL:         ttl,
		KeyBits:     req.KeyBits,
	})
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "sign leaf certificate", err)
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

	result := &IssueResult{
		CertPEM:       string(certPEM),
		PrivateKeyPEM: string(keyPEM),
		Serial:        serial,
		ExpiresAt:     expiresAt,
	}
	if e.issued != nil {
		ttlSeconds := int(ttl.Seconds())
		if ttlSeconds <= 0 {
			ttlSeconds = int(expiresAt.Sub(time.Now().UTC()).Seconds())
		}
		record := &domainpki.IssuedCertificate{
			ID:         uuid.New(),
			CAID:       ca.ID,
			Role:       req.Role,
			Serial:     serial,
			CommonName: req.CommonName,
			DNSNames:   append([]string(nil), req.DNSNames...),
			TTLSeconds: ttlSeconds,
			IssuedAt:   time.Now().UTC(),
			ExpiresAt:  expiresAt,
			AutoRenew:  req.AutoRenew,
		}
		if err := e.issued.Save(ctx, record); err != nil {
			return nil, err
		}
	}
	return result, nil
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
	defer memzero.Bytes(caKey)

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

// ImportCARequest imports a CA from PEM material.
type ImportCARequest struct {
	Name       string
	CommonName string
	CertPEM    string
	KeyPEM     string
	ParentName string
}

// ExportCAResult returns public CA material.
type ExportCAResult struct {
	ID        uuid.UUID
	Name      string
	CertPEM   string
	ChainPEM  string
	Serial    string
	ExpiresAt time.Time
}

// ImportCA stores an imported CA with encrypted private key.
func (e *Engine) ImportCA(ctx context.Context, req ImportCARequest) (*CAResult, error) {
	if e.crypto == nil || e.caRepo == nil {
		return nil, common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}
	if req.Name == "" || req.CertPEM == "" || req.KeyPEM == "" {
		return nil, common.New(common.ErrCodeValidation, "name, cert_pem, and key_pem are required")
	}
	serial, expiresAt, err := parseCertMetadata([]byte(req.CertPEM))
	if err != nil {
		return nil, common.Wrap(common.ErrCodeValidation, "invalid certificate", err)
	}
	keyEnc, dekEnc, err := e.crypto.Seal([]byte(req.KeyPEM))
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "encrypt private key", err)
	}
	caType := domainpki.CATypeRoot
	var parentID *uuid.UUID
	if req.ParentName != "" {
		parent, err := e.caRepo.GetByName(ctx, req.ParentName)
		if err != nil {
			return nil, err
		}
		caType = domainpki.CATypeIntermediate
		pid := parent.ID
		parentID = &pid
	}
	cn := req.CommonName
	if cn == "" {
		cn = req.Name
	}
	ca := &domainpki.CA{
		ID:            uuid.New(),
		ParentID:      parentID,
		Name:          req.Name,
		Type:          caType,
		Subject:       domainpki.DistinguishedName{CommonName: cn},
		Serial:        serial,
		CertPEM:       req.CertPEM,
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

// ExportCA returns certificate chain without private key.
func (e *Engine) ExportCA(ctx context.Context, id uuid.UUID) (*ExportCAResult, error) {
	if e.caRepo == nil {
		return nil, common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}
	ca, err := e.caRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	chain := ca.CertPEM
	if ca.ParentID != nil {
		parent, err := e.caRepo.GetByID(ctx, *ca.ParentID)
		if err == nil {
			chain = ca.CertPEM + "\n" + parent.CertPEM
		}
	}
	return &ExportCAResult{
		ID:        ca.ID,
		Name:      ca.Name,
		CertPEM:   ca.CertPEM,
		ChainPEM:  chain,
		Serial:    ca.Serial,
		ExpiresAt: ca.ExpiresAt,
	}, nil
}

// RotateCA creates a successor CA (stub workflow).
func (e *Engine) RotateCA(ctx context.Context, id uuid.UUID) (*CAResult, error) {
	if e.caRepo == nil {
		return nil, common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}
	old, err := e.caRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf("%s-successor-%d", old.Name, time.Now().Unix())
	if old.Type == domainpki.CATypeRoot {
		return e.CreateRoot(ctx, CreateRootRequest{
			Name:       name,
			CommonName: old.Subject.CommonName + " Successor",
			TTL:        "8760h",
		})
	}
	parentName := old.Name
	if old.ParentID != nil {
		parent, err := e.caRepo.GetByID(ctx, *old.ParentID)
		if err == nil {
			parentName = parent.Name
		}
	}
	return e.CreateIntermediate(ctx, CreateIntermediateRequest{
		ParentName: parentName,
		Name:       name,
		CommonName: old.Subject.CommonName + " Successor",
		TTL:        "4380h",
	})
}

func validateIssueAgainstRole(role *domainpki.Role, req IssueRequest) error {
	for _, dns := range req.DNSNames {
		if !role.AllowedDomain(dns) {
			return common.New(common.ErrCodeValidation, fmt.Sprintf("dns name %q not allowed by role", dns))
		}
	}
	if req.TTL != "" && role.MaxTTLSeconds > 0 {
		ttl, err := utils.ParseTTL(req.TTL)
		if err != nil {
			return common.Wrap(common.ErrCodeValidation, "invalid ttl", err)
		}
		if int(ttl.Seconds()) > role.MaxTTLSeconds {
			return common.New(common.ErrCodeValidation, "ttl exceeds role maximum")
		}
	}
	return nil
}
