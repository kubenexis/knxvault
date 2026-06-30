// Package service orchestrates business workflows.
package service

import (
	"context"

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
