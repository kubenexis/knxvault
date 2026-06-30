// Package audit provides append-only audit logging (LLD §4.D).
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kubenexis/knxvault/internal/domain/audit"
	"github.com/kubenexis/knxvault/internal/repository"
)

// Service appends immutable audit entries with hash chaining.
type Service struct {
	repo       repository.AuditRepository
	signingKey []byte
}

// NewService constructs an audit service.
func NewService(repo repository.AuditRepository) *Service {
	return &Service{repo: repo}
}

// SetSigningKey enables HMAC signing of exported audit chain heads.
func (s *Service) SetSigningKey(key []byte) {
	s.signingKey = key
}

// Record appends an audit entry.
func (s *Service) Record(ctx context.Context, actor, action, resource, status string, details map[string]any) error {
	if s.repo == nil {
		return fmt.Errorf("audit repository not configured")
	}

	prevHash, err := s.repo.LatestHash(ctx)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	entry := &audit.Entry{
		Timestamp: now,
		Actor:     actor,
		Action:    action,
		Resource:  resource,
		Status:    status,
		Details:   details,
		Hash:      computeHash(prevHash, actor, action, resource, status, details, now),
	}
	return s.repo.Append(ctx, entry)
}

// ExportResult contains audit entries and integrity metadata.
type ExportResult struct {
	Entries   []*audit.Entry
	HeadHash  string
	Signature string
	SignedAt  time.Time
}

// Export returns audit entries and an optional signed chain head.
func (s *Service) Export(ctx context.Context, opts repository.AuditListOptions) (*ExportResult, error) {
	if s.repo == nil {
		return nil, fmt.Errorf("audit repository not configured")
	}
	opts.OrderAsc = true
	entries, err := s.repo.List(ctx, opts)
	if err != nil {
		return nil, err
	}
	headHash, err := s.repo.LatestHash(ctx)
	if err != nil {
		return nil, err
	}
	result := &ExportResult{
		Entries:  entries,
		HeadHash: headHash,
		SignedAt: time.Now().UTC(),
	}
	if len(s.signingKey) > 0 && headHash != "" {
		result.Signature = signHead(s.signingKey, headHash, result.SignedAt)
	}
	return result, nil
}

// VerifyResult reports audit chain integrity status.
type VerifyResult struct {
	Valid     bool
	HeadHash  string
	Signature string
	Message   string
}

// Verify checks hash chain integrity and optional HMAC signature.
func (s *Service) Verify(ctx context.Context, signature string, signedAt time.Time) (*VerifyResult, error) {
	if s.repo == nil {
		return nil, fmt.Errorf("audit repository not configured")
	}

	entries, err := s.repo.List(ctx, repository.AuditListOptions{OrderAsc: true, Limit: 1_000_000})
	if err != nil {
		return nil, err
	}

	prevHash := ""
	for _, entry := range entries {
		expected := computeHash(prevHash, entry.Actor, entry.Action, entry.Resource, entry.Status, entry.Details, entry.Timestamp)
		if entry.Hash != expected {
			return &VerifyResult{
				Valid:    false,
				HeadHash: entry.Hash,
				Message:  fmt.Sprintf("hash mismatch at entry id %d", entry.ID),
			}, nil
		}
		prevHash = entry.Hash
	}

	headHash, err := s.repo.LatestHash(ctx)
	if err != nil {
		return nil, err
	}
	if headHash != prevHash {
		return &VerifyResult{
			Valid:    false,
			HeadHash: headHash,
			Message:  "head hash does not match recomputed chain",
		}, nil
	}

	result := &VerifyResult{Valid: true, HeadHash: headHash}
	if len(s.signingKey) > 0 {
		if signature == "" {
			result.Valid = false
			result.Message = "signature required when signing key is configured"
			return result, nil
		}
		expected := signHead(s.signingKey, headHash, signedAt)
		result.Signature = signature
		if !hmac.Equal([]byte(signature), []byte(expected)) {
			result.Valid = false
			result.Message = "signature mismatch"
		}
	}
	return result, nil
}

func computeHash(prevHash, actor, action, resource, status string, details map[string]any, ts time.Time) string {
	if details == nil {
		details = map[string]any{}
	}
	detailsJSON, _ := json.Marshal(details)
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		prevHash,
		ts.Format(time.RFC3339Nano),
		actor,
		action,
		resource,
		status,
		string(detailsJSON),
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func signHead(key []byte, headHash string, signedAt time.Time) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(headHash))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(signedAt.Format(time.RFC3339Nano)))
	return hex.EncodeToString(mac.Sum(nil))
}
