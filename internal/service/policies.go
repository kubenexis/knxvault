package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

// PolicyService manages persisted RBAC policies and roles.
type PolicyService struct {
	policies   repository.PolicyRepository
	roles      repository.RoleRepository
	rbac       *auth.RBAC
	audit      *auditsvc.Service
	policyHash string
	hashMu     sync.Mutex
}

// NewPolicyService constructs a policy service.
func NewPolicyService(
	policies repository.PolicyRepository,
	roles repository.RoleRepository,
	rbac *auth.RBAC,
	audit *auditsvc.Service,
) *PolicyService {
	return &PolicyService{
		policies: policies,
		roles:    roles,
		rbac:     rbac,
		audit:    audit,
	}
}

// SavePolicy persists and activates a policy.
func (s *PolicyService) SavePolicy(ctx context.Context, policy *domainauth.Policy) error {
	err := s.policies.Save(ctx, policy)
	if err == nil && s.rbac != nil {
		s.hashMu.Lock()
		s.rbac.UpsertPolicy(*policy)
		s.policyHash = ""
		s.hashMu.Unlock()
	}
	audithelper.Record(s.audit, ctx, "policy.write", "sys/policies/"+policy.Name, err, nil)
	return err
}

// GetPolicy returns a policy by name.
func (s *PolicyService) GetPolicy(ctx context.Context, name string) (*domainauth.Policy, error) {
	return s.policies.GetByName(ctx, name)
}

// ListPolicies returns all persisted policies.
func (s *PolicyService) ListPolicies(ctx context.Context) ([]*domainauth.Policy, error) {
	return s.policies.List(ctx)
}

// DeletePolicy removes a policy.
func (s *PolicyService) DeletePolicy(ctx context.Context, name string) error {
	err := s.policies.Delete(ctx, name)
	if err == nil && s.rbac != nil {
		s.hashMu.Lock()
		s.rbac.DeletePolicy(name)
		s.policyHash = ""
		s.hashMu.Unlock()
	}
	audithelper.Record(s.audit, ctx, "policy.delete", "sys/policies/"+name, err, nil)
	return err
}

// SaveRole persists a role binding.
func (s *PolicyService) SaveRole(ctx context.Context, role *domainauth.Role) error {
	err := s.roles.Save(ctx, role)
	audithelper.Record(s.audit, ctx, "role.write", "sys/roles/"+role.Name, err, nil)
	return err
}

// GetRole returns a role by name.
func (s *PolicyService) GetRole(ctx context.Context, name string) (*domainauth.Role, error) {
	return s.roles.Get(ctx, name)
}

// ListRoles returns all persisted roles.
func (s *PolicyService) ListRoles(ctx context.Context) ([]*domainauth.Role, error) {
	return s.roles.List(ctx)
}

// DeleteRole removes a role.
func (s *PolicyService) DeleteRole(ctx context.Context, name string) error {
	err := s.roles.Delete(ctx, name)
	audithelper.Record(s.audit, ctx, "role.delete", "sys/roles/"+name, err, nil)
	return err
}

// LoadIntoRBAC reloads persisted policies on top of built-in defaults.
func (s *PolicyService) LoadIntoRBAC(ctx context.Context) error {
	if s.policies == nil || s.rbac == nil {
		return nil
	}
	s.hashMu.Lock()
	defer s.hashMu.Unlock()

	policies, err := s.policies.List(ctx)
	if err != nil {
		return err
	}
	s.rbac.ReloadFromPersisted(policies)
	s.policyHash = hashPolicies(policies)
	return nil
}

// SyncRBAC reloads persisted policies when the cluster policy set has changed.
func (s *PolicyService) SyncRBAC(ctx context.Context) error {
	if s.policies == nil || s.rbac == nil {
		return nil
	}
	s.hashMu.Lock()
	defer s.hashMu.Unlock()

	policies, err := s.policies.List(ctx)
	if err != nil {
		return err
	}
	hash := hashPolicies(policies)
	if hash == s.policyHash && s.policyHash != "" {
		return nil
	}
	s.rbac.ReloadFromPersisted(policies)
	s.policyHash = hash
	return nil
}

func (s *PolicyService) invalidatePolicyHash() {
	s.hashMu.Lock()
	s.policyHash = ""
	s.hashMu.Unlock()
}

func hashPolicies(policies []*domainauth.Policy) string {
	if len(policies) == 0 {
		return ""
	}
	sorted := append([]*domainauth.Policy(nil), policies...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	payload, _ := json.Marshal(sorted)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
