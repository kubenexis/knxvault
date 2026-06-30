// Package service orchestrates business workflows.
package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	domainpki "github.com/kubenexis/knxvault/internal/domain/pki"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
)

// PKIService coordinates PKI operations with audit logging.
type PKIService struct {
	engine *pkiengine.Engine
	audit  *auditsvc.Service
}

// NewPKIService constructs a PKI service.
func NewPKIService(engine *pkiengine.Engine, audit *auditsvc.Service) *PKIService {
	return &PKIService{engine: engine, audit: audit}
}

func (s *PKIService) actor(ctx context.Context) string {
	if principal, ok := auth.PrincipalFromContext(ctx); ok {
		return principal.Subject
	}
	return "anonymous"
}

// CreateRoot creates a root CA.
func (s *PKIService) CreateRoot(ctx context.Context, req pkiengine.CreateRootRequest) (*pkiengine.CAResult, error) {
	result, err := s.engine.CreateRoot(ctx, req)
	s.record(ctx, "pki.root.create", "pki/"+req.Name, err, nil)
	return result, err
}

// CreateIntermediate creates an intermediate CA.
func (s *PKIService) CreateIntermediate(ctx context.Context, req pkiengine.CreateIntermediateRequest) (*pkiengine.CAResult, error) {
	result, err := s.engine.CreateIntermediate(ctx, req)
	s.record(ctx, "pki.intermediate.create", "pki/"+req.Name, err, nil)
	return result, err
}

// IssueCertificate issues a leaf certificate.
func (s *PKIService) IssueCertificate(ctx context.Context, req pkiengine.IssueRequest) (*pkiengine.IssueResult, error) {
	result, err := s.engine.IssueCertificate(ctx, req)
	s.record(ctx, "pki.issue", "pki/"+req.Role, err, map[string]any{"common_name": req.CommonName})
	return result, err
}

// GetCA returns a CA by ID.
func (s *PKIService) GetCA(ctx context.Context, id uuid.UUID) (*domainpki.CA, error) {
	return s.engine.GetCA(ctx, id)
}

// Revoke revokes a certificate serial.
func (s *PKIService) Revoke(ctx context.Context, caID uuid.UUID, serial, reason string) error {
	err := s.engine.Revoke(ctx, caID, serial, reason)
	s.record(ctx, "pki.revoke", "pki/"+serial, err, map[string]any{"ca_id": caID.String()})
	return err
}

// GenerateCRL returns a PEM CRL.
func (s *PKIService) GenerateCRL(ctx context.Context, caID uuid.UUID) (string, error) {
	result, err := s.engine.GenerateCRL(ctx, caID)
	s.record(ctx, "pki.crl.generate", "pki/"+caID.String(), err, nil)
	return result, err
}

// RenewCertificate re-issues a certificate from stored metadata.
func (s *PKIService) RenewCertificate(ctx context.Context, req pkiengine.RenewRequest) (*pkiengine.RenewResult, error) {
	result, err := s.engine.RenewCertificate(ctx, req)
	s.record(ctx, "pki.renew", "pki/"+req.Serial, err, map[string]any{"ca_id": req.CAID.String()})
	return result, err
}

// ImportCA imports PEM CA material.
func (s *PKIService) ImportCA(ctx context.Context, req pkiengine.ImportCARequest) (*pkiengine.CAResult, error) {
	result, err := s.engine.ImportCA(ctx, req)
	s.record(ctx, "pki.ca.import", "pki/"+req.Name, err, nil)
	return result, err
}

// ExportCA exports public CA chain.
func (s *PKIService) ExportCA(ctx context.Context, id uuid.UUID) (*pkiengine.ExportCAResult, error) {
	result, err := s.engine.ExportCA(ctx, id)
	s.record(ctx, "pki.ca.export", "pki/"+id.String(), err, nil)
	return result, err
}

// RotateCA creates a successor CA.
func (s *PKIService) RotateCA(ctx context.Context, id uuid.UUID) (*pkiengine.CAResult, error) {
	result, err := s.engine.RotateCA(ctx, id)
	s.record(ctx, "pki.ca.rotate", "pki/"+id.String(), err, nil)
	return result, err
}

// HandleOCSP processes an OCSP request and returns a DER response.
func (s *PKIService) HandleOCSP(ctx context.Context, caID uuid.UUID, requestDER []byte) ([]byte, error) {
	result, err := s.engine.HandleOCSP(ctx, caID, requestDER)
	s.record(ctx, "pki.ocsp", "pki/ocsp/"+caID.String(), err, nil)
	return result, err
}

// RenewExpiring renews certificates within the configured grace window.
func (s *PKIService) RenewExpiring(ctx context.Context, grace time.Duration, limit int) (int, error) {
	count, err := s.engine.RenewExpiring(ctx, grace, limit)
	if err == nil && count > 0 {
		s.record(ctx, "pki.renew.batch", "pki/renew", nil, map[string]any{"count": count})
	}
	return count, err
}

func (s *PKIService) record(ctx context.Context, action, resource string, err error, details map[string]any) {
	if s.audit == nil {
		return
	}
	status := "success"
	if err != nil {
		status = "failure"
	}
	_ = s.audit.Record(ctx, s.actor(ctx), action, resource, status, details)
}
