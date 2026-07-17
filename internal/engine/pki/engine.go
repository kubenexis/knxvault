// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/kubenexis/knxvault/internal/crypto/memzero"
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
	// AllowedDomains for the auto-created PKI role named after the CA (W78).
	// Empty keeps the deny-default role (_unconfigured.invalid) until operators update domains.
	AllowedDomains  []string
	AllowSubdomains bool
}

// CreateIntermediateRequest configures a new intermediate CA.
type CreateIntermediateRequest struct {
	ParentName string
	Name       string
	CommonName string
	TTL        string
	KeyBits    int
	// AllowedDomains for the auto-created PKI role named after the CA (W78).
	AllowedDomains  []string
	AllowSubdomains bool
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
	CAID          uuid.UUID // signing CA id (for operator renew)
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

// NewEngine constructs a PKI engine using the native Go crypto/x509 backend.
// OpenSSL CLI is not used (distroless-only packaging).
func NewEngine(
	cryptoSvc *kvncrypto.Service,
	caRepo repository.CARepository,
	revoked repository.RevocationRepository,
) *Engine {
	return &Engine{
		backend: pkibackend.NewNativeBackend(),
		crypto:  cryptoSvc,
		caRepo:  caRepo,
		revoked: revoked,
	}
}

// SetBackend replaces the PKI issuance backend (tests only).
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
	e.ensureDefaultRole(ctx, ca.Name, req.AllowedDomains, req.AllowSubdomains)

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
	e.ensureDefaultRole(ctx, ca.Name, req.AllowedDomains, req.AllowSubdomains)

	return &CAResult{
		ID:        ca.ID,
		Name:      ca.Name,
		CertPEM:   ca.CertPEM,
		Serial:    ca.Serial,
		ExpiresAt: ca.ExpiresAt,
	}, nil
}

// defaultLeafTTL is the default leaf lifetime when role has no MaxTTL (W52).
const defaultLeafTTL = 72 * time.Hour

// IssueCertificate issues a leaf certificate signed by the named CA role.
func (e *Engine) IssueCertificate(ctx context.Context, req IssueRequest) (*IssueResult, error) {
	if e.crypto == nil || e.caRepo == nil || e.backend == nil {
		return nil, common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}

	caName, pkiRole, err := e.resolvePKIRole(ctx, req.Role)
	if err != nil {
		return nil, err
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

	ttl := defaultLeafTTL
	if req.TTL != "" {
		ttl, err = utils.ParseTTL(req.TTL)
		if err != nil {
			return nil, common.Wrap(common.ErrCodeValidation, "invalid ttl", err)
		}
	}
	if pkiRole != nil && pkiRole.MaxTTLSeconds > 0 {
		max := time.Duration(pkiRole.MaxTTLSeconds) * time.Second
		if ttl > max {
			if req.TTL != "" {
				return nil, common.New(common.ErrCodeValidation, "ttl exceeds role maximum")
			}
			ttl = max
		}
	}
	caKey, err := e.decryptKey(ca.PrivateKeyEnc, ca.DEKEnc)
	if err != nil {
		return nil, err
	}
	defer memzero.Bytes(caKey)

	usage := domainpki.RoleUsageServer
	if pkiRole != nil && pkiRole.KeyUsage != "" {
		usage = pkiRole.KeyUsage
	}
	certPEM, keyPEM, err := e.backend.IssueCertificate(ctx, pkibackend.IssueRequest{
		CACertPEM:   []byte(ca.CertPEM),
		CAKeyPEM:    caKey,
		CommonName:  req.CommonName,
		DNSNames:    req.DNSNames,
		IPAddresses: req.IPAddresses,
		TTL:         ttl,
		KeyBits:     req.KeyBits,
		KeyUsage:    string(usage),
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
		CAID:          ca.ID,
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

// GetCAByName returns a CA by vault name.
func (e *Engine) GetCAByName(ctx context.Context, name string) (*domainpki.CA, error) {
	if e.caRepo == nil {
		return nil, common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}
	if strings.TrimSpace(name) == "" {
		return nil, common.New(common.ErrCodeValidation, "name is required")
	}
	return e.caRepo.GetByName(ctx, name)
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
	// W78: monotonic CRL number (unix nanos) — avoid fixed "1" across updates.
	tmpl := &x509.RevocationList{
		RevokedCertificateEntries: make([]x509.RevocationListEntry, 0, len(revoked)),
		Number:                    big.NewInt(now.UnixNano()),
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

// verifyCertKeyMatch ensures the PEM private key corresponds to the certificate public key.
func verifyCertKeyMatch(certPEM, keyPEM []byte) error {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return err
	}
	signer, err := parseSigner(keyPEM)
	if err != nil {
		return err
	}
	switch pub := cert.PublicKey.(type) {
	case interface{ Equal(crypto.PublicKey) bool }:
		if !pub.Equal(signer.Public()) {
			return fmt.Errorf("public key mismatch")
		}
	default:
		// Fallback: compare SPKI DER encodings.
		want, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return err
		}
		got, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil {
			return err
		}
		if string(want) != string(got) {
			return fmt.Errorf("public key mismatch")
		}
	}
	return nil
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
	// W78: prove private key matches certificate before sealing.
	if err := verifyCertKeyMatch([]byte(req.CertPEM), []byte(req.KeyPEM)); err != nil {
		return nil, common.Wrap(common.ErrCodeValidation, "certificate and private key do not match", err)
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

// SignCSRRequest configures CSR signing for a PKI role.
type SignCSRRequest struct {
	Role   string
	CSRPEM string
	TTL    string
}

// SignCSRResult is returned when signing a CSR.
type SignCSRResult struct {
	CertPEM   string
	Serial    string
	ExpiresAt time.Time
	CAChain   []string
}

// SignCSR signs a PEM CSR using the CA bound to a PKI role.
// When a PKI role defines AllowedDomains / MaxTTL, CSR names and TTL are enforced
// the same way as IssueCertificate (security audit: CSR path must not bypass role policy).
func (e *Engine) SignCSR(ctx context.Context, req SignCSRRequest) (*SignCSRResult, error) {
	if e.crypto == nil || e.caRepo == nil || e.backend == nil {
		return nil, common.New(common.ErrCodeInternal, "pki engine not fully configured")
	}
	if strings.TrimSpace(req.CSRPEM) == "" {
		return nil, common.New(common.ErrCodeValidation, "csr is required")
	}

	// W52-03: require a persisted PKI role when role repository is configured
	// (no unconstrained CA-name-only sign path).
	caName, pkiRole, err := e.resolvePKIRole(ctx, req.Role)
	if err != nil {
		return nil, err
	}

	ca, err := e.caRepo.GetByName(ctx, caName)
	if err != nil {
		return nil, err
	}

	if pkiRole != nil {
		if err := validateCSRAgainstRole(pkiRole, req.CSRPEM, req.TTL); err != nil {
			return nil, err
		}
	}

	ttl := defaultLeafTTL
	if req.TTL != "" {
		ttl, err = utils.ParseTTL(req.TTL)
		if err != nil {
			return nil, common.Wrap(common.ErrCodeValidation, "invalid ttl", err)
		}
	}
	if pkiRole != nil && pkiRole.MaxTTLSeconds > 0 {
		max := time.Duration(pkiRole.MaxTTLSeconds) * time.Second
		if ttl > max {
			return nil, common.New(common.ErrCodeValidation, "ttl exceeds role maximum")
		}
	}

	caKey, err := e.decryptKey(ca.PrivateKeyEnc, ca.DEKEnc)
	if err != nil {
		return nil, err
	}
	defer memzero.Bytes(caKey)

	usage := domainpki.RoleUsageServer
	if pkiRole != nil && pkiRole.KeyUsage != "" {
		usage = pkiRole.KeyUsage
	}
	certPEM, err := e.backend.SignCSR(ctx, pkibackend.SignCSRRequest{
		CSRPEM:    []byte(req.CSRPEM),
		CACertPEM: []byte(ca.CertPEM),
		CAKeyPEM:  caKey,
		TTL:       ttl,
		KeyUsage:  string(usage),
	})
	if err != nil {
		return nil, common.Wrap(common.ErrCodeInternal, "sign csr", err)
	}

	serial, expiresAt, err := parseCertMetadata(certPEM)
	if err != nil {
		return nil, err
	}

	chain := []string{ca.CertPEM}
	if ca.ParentID != nil {
		if parent, parentErr := e.caRepo.GetByID(ctx, *ca.ParentID); parentErr == nil {
			chain = append([]string{parent.CertPEM}, chain...)
		}
	}

	return &SignCSRResult{
		CertPEM:   string(certPEM),
		Serial:    serial,
		ExpiresAt: expiresAt,
		CAChain:   chain,
	}, nil
}

func (e *Engine) ensureDefaultRole(ctx context.Context, caName string, allowedDomains []string, allowSubdomains bool) {
	if e == nil || e.roleRepo == nil || caName == "" {
		return
	}
	if _, err := e.roleRepo.Get(ctx, caName); err == nil {
		return
	}
	// W78-04: vault-compat "role == CA name". Default deny until AllowedDomains is set
	// (explicit "*" only when unconstrained issuance is intentional).
	domains := normalizeDomains(allowedDomains)
	if len(domains) == 0 {
		domains = []string{"_unconfigured.invalid"}
	}
	_ = e.roleRepo.Save(ctx, &domainpki.Role{
		Name:            caName,
		CAName:          caName,
		AllowedDomains:  domains,
		AllowSubdomains: allowSubdomains,
		KeyUsage:        domainpki.RoleUsageServer,
		MaxTTLSeconds:   0,
	})
}

func normalizeDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// SaveRole persists or replaces a PKI issuance role (W78 ops path).
func (e *Engine) SaveRole(ctx context.Context, role *domainpki.Role) error {
	if e == nil || e.roleRepo == nil {
		return common.New(common.ErrCodeInternal, "pki role repository not configured")
	}
	if role == nil {
		return common.New(common.ErrCodeValidation, "role is required")
	}
	if err := role.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid pki role", err)
	}
	return e.roleRepo.Save(ctx, role)
}

func (e *Engine) resolvePKIRole(ctx context.Context, roleName string) (caName string, role *domainpki.Role, err error) {
	roleName = strings.TrimSpace(roleName)
	if roleName == "" {
		roleName = "root"
	}
	if e.roleRepo == nil {
		return roleName, nil, nil
	}
	r, err := e.roleRepo.Get(ctx, roleName)
	if err != nil {
		return "", nil, common.Wrap(common.ErrCodeNotFound, "pki role not found (create a role or use a CA name after CreateRoot which installs a default \"*\" role)", err)
	}
	return r.CAName, r, nil
}

func validateIssueAgainstRole(role *domainpki.Role, req IssueRequest) error {
	if cn := strings.TrimSpace(req.CommonName); cn != "" && !role.AllowedDomain(cn) {
		return common.New(common.ErrCodeValidation, fmt.Sprintf("common name %q not allowed by role", cn))
	}
	for _, dns := range req.DNSNames {
		if !role.AllowedDomain(dns) {
			return common.New(common.ErrCodeValidation, fmt.Sprintf("dns name %q not allowed by role", dns))
		}
	}
	// W51-05 / W52: IP SANs require explicit "*" domain (unconstrained) roles.
	if len(req.IPAddresses) > 0 && !role.AllowsAnyDomain() {
		return common.New(common.ErrCodeValidation, "ip SANs are not allowed by role domain policy (use allowed_domains: [\"*\"] if required)")
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

// validateCSRAgainstRole enforces AllowedDomains and MaxTTL on CSR contents before signing.
// W78: EmailAddresses and URIs are denied unless the role is unconstrained ("*").
func validateCSRAgainstRole(role *domainpki.Role, csrPEM, ttl string) error {
	if role == nil {
		return nil
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return common.New(common.ErrCodeValidation, "invalid csr pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return common.Wrap(common.ErrCodeValidation, "parse csr", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid csr signature", err)
	}
	// Collect names: CN + DNS SANs. IP SANs require AllowsAnyDomain (W51-05).
	if len(csr.IPAddresses) > 0 && !role.AllowsAnyDomain() {
		return common.New(common.ErrCodeValidation, "csr ip SANs are not allowed by role domain policy")
	}
	// W78-01: email/URI SANs must not bypass domain-restricted roles.
	if len(csr.EmailAddresses) > 0 && !role.AllowsAnyDomain() {
		return common.New(common.ErrCodeValidation, "csr email SANs are not allowed by role domain policy (use allowed_domains: [\"*\"] if required)")
	}
	if len(csr.URIs) > 0 && !role.AllowsAnyDomain() {
		return common.New(common.ErrCodeValidation, "csr URI SANs are not allowed by role domain policy (use allowed_domains: [\"*\"] if required)")
	}
	names := make([]string, 0, 1+len(csr.DNSNames))
	if cn := strings.TrimSpace(csr.Subject.CommonName); cn != "" {
		names = append(names, cn)
	}
	names = append(names, csr.DNSNames...)
	if !role.AllowsAnyDomain() && len(names) == 0 {
		return common.New(common.ErrCodeValidation, "csr has no common name or dns names to validate against role")
	}
	for _, name := range names {
		if !role.AllowedDomain(name) {
			return common.New(common.ErrCodeValidation, fmt.Sprintf("csr name %q not allowed by role", name))
		}
	}
	if ttl != "" && role.MaxTTLSeconds > 0 {
		d, err := utils.ParseTTL(ttl)
		if err != nil {
			return common.Wrap(common.ErrCodeValidation, "invalid ttl", err)
		}
		if int(d.Seconds()) > role.MaxTTLSeconds {
			return common.New(common.ErrCodeValidation, "ttl exceeds role maximum")
		}
	}
	return nil
}
