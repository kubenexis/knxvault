// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/crypto"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

const identityBlobPath = "sys/internal/identity"

// IdentityService manages entities, aliases, and groups (M-IDENT-1 / W74-05).
type IdentityService struct {
	mu       sync.RWMutex
	entities map[string]*domainauth.Entity
	aliases  map[string]*domainauth.Alias
	byMount  map[string]string
	groups   map[string]*domainauth.Group
	audit    *auditsvc.Service
	repo     repository.SecretRepository
	crypto   *crypto.Service
	// optional: known policy names for assignment allowlist
	policyExists func(ctx context.Context, name string) bool
}

// NewIdentityService constructs an identity service.
func NewIdentityService(audit *auditsvc.Service) *IdentityService {
	return &IdentityService{
		entities: make(map[string]*domainauth.Entity),
		aliases:  make(map[string]*domainauth.Alias),
		byMount:  make(map[string]string),
		groups:   make(map[string]*domainauth.Group),
		audit:    audit,
	}
}

// AttachStorage enables sealed persistence of the identity snapshot.
func (s *IdentityService) AttachStorage(repo repository.SecretRepository, cryptoSvc *crypto.Service) {
	if s == nil {
		return
	}
	s.repo = repo
	s.crypto = cryptoSvc
	_ = s.load(context.Background())
}

// SetPolicyExists configures a callback to validate policy names (W74-11).
func (s *IdentityService) SetPolicyExists(fn func(ctx context.Context, name string) bool) {
	if s != nil {
		s.policyExists = fn
	}
}

type identitySnapshot struct {
	Entities []*domainauth.Entity `json:"entities"`
	Aliases  []*domainauth.Alias  `json:"aliases"`
	Groups   []*domainauth.Group  `json:"groups"`
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func (s *IdentityService) validatePolicies(ctx context.Context, policies []string) error {
	if s.policyExists == nil {
		return nil
	}
	for _, p := range policies {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !s.policyExists(ctx, p) {
			return common.New(common.ErrCodeValidation, "unknown policy: "+p)
		}
	}
	return nil
}

// CreateEntity creates an entity.
func (s *IdentityService) CreateEntity(ctx context.Context, name string, policies []string, metadata map[string]string) (*domainauth.Entity, error) {
	if s == nil {
		return nil, common.New(common.ErrCodeInternal, "identity not configured")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, common.New(common.ErrCodeValidation, "name required")
	}
	if err := s.validatePolicies(ctx, policies); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	e := &domainauth.Entity{
		ID:       newID("ent_"),
		Name:     name,
		Policies: append([]string(nil), policies...),
		Metadata: metadata,
		Created:  now,
		Updated:  now,
	}
	if err := e.Validate(); err != nil {
		return nil, common.Wrap(common.ErrCodeValidation, "entity", err)
	}
	s.mu.Lock()
	s.entities[e.ID] = e
	err := s.persistLocked(ctx)
	s.mu.Unlock()
	audithelper.Record(s.audit, ctx, "identity.entity.create", "identity/entity/"+e.ID, err, map[string]any{"name": name})
	if err != nil {
		return nil, err
	}
	return cloneEntity(e), nil
}

// GetEntity returns an entity by id.
func (s *IdentityService) GetEntity(ctx context.Context, id string) (*domainauth.Entity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entities[id]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "entity not found")
	}
	_ = ctx
	return cloneEntity(e), nil
}

// SetEntityDisabled disables or enables an entity.
func (s *IdentityService) SetEntityDisabled(ctx context.Context, id string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entities[id]
	if !ok {
		return common.New(common.ErrCodeNotFound, "entity not found")
	}
	e.Disabled = disabled
	e.Updated = time.Now().UTC()
	err := s.persistLocked(ctx)
	audithelper.Record(s.audit, ctx, "identity.entity.disable", "identity/entity/"+id, err, map[string]any{"disabled": disabled})
	return err
}

// CreateAlias links mount+name to an entity.
func (s *IdentityService) CreateAlias(ctx context.Context, entityID, mount, name string) (*domainauth.Alias, error) {
	mount = strings.ToLower(strings.TrimSpace(mount))
	name = strings.TrimSpace(name)
	if mount == "" || name == "" {
		return nil, common.New(common.ErrCodeValidation, "mount and name required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entities[entityID]; !ok {
		return nil, common.New(common.ErrCodeNotFound, "entity not found")
	}
	key := mount + "\x00" + name
	if _, ok := s.byMount[key]; ok {
		return nil, common.New(common.ErrCodeValidation, "alias already exists")
	}
	a := &domainauth.Alias{
		ID:       newID("alias_"),
		EntityID: entityID,
		Mount:    mount,
		Name:     name,
		Created:  time.Now().UTC(),
	}
	s.aliases[a.ID] = a
	s.byMount[key] = a.ID
	err := s.persistLocked(ctx)
	audithelper.Record(s.audit, ctx, "identity.alias.create", "identity/alias/"+a.ID, err, map[string]any{"mount": mount})
	if err != nil {
		return nil, err
	}
	cp := *a
	return &cp, nil
}

// CreateGroup creates a group.
func (s *IdentityService) CreateGroup(ctx context.Context, name string, members, policies []string) (*domainauth.Group, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, common.New(common.ErrCodeValidation, "name required")
	}
	if err := s.validatePolicies(ctx, policies); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	g := &domainauth.Group{
		ID:        newID("grp_"),
		Name:      name,
		MemberIDs: append([]string(nil), members...),
		Policies:  append([]string(nil), policies...),
		Created:   now,
		Updated:   now,
	}
	s.mu.Lock()
	s.groups[g.ID] = g
	err := s.persistLocked(ctx)
	s.mu.Unlock()
	audithelper.Record(s.audit, ctx, "identity.group.create", "identity/group/"+g.ID, err, map[string]any{"name": name})
	if err != nil {
		return nil, err
	}
	cp := *g
	return &cp, nil
}

// ResolveLogin returns entity id and merged policies for an auth alias.
func (s *IdentityService) ResolveLogin(ctx context.Context, mount, aliasName string, basePolicies []string) (entityID string, policies []string, err error) {
	if s == nil {
		return "", basePolicies, nil
	}
	mount = strings.ToLower(strings.TrimSpace(mount))
	s.mu.RLock()
	defer s.mu.RUnlock()
	aid, ok := s.byMount[mount+"\x00"+aliasName]
	if !ok {
		return "", basePolicies, nil
	}
	a := s.aliases[aid]
	e := s.entities[a.EntityID]
	if e == nil {
		return "", basePolicies, nil
	}
	if e.Disabled {
		return "", nil, common.New(common.ErrCodeForbidden, "entity disabled")
	}
	pol := uniqueStrings(append(append([]string{}, basePolicies...), e.Policies...))
	for _, g := range s.groups {
		for _, mid := range g.MemberIDs {
			if mid == e.ID {
				pol = uniqueStrings(append(pol, g.Policies...))
				break
			}
		}
	}
	_ = ctx
	return e.ID, pol, nil
}

// ListEntities returns all entities.
func (s *IdentityService) ListEntities(ctx context.Context) []*domainauth.Entity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*domainauth.Entity, 0, len(s.entities))
	for _, e := range s.entities {
		out = append(out, cloneEntity(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	_ = ctx
	return out
}

// ListGroups returns all groups.
func (s *IdentityService) ListGroups(ctx context.Context) []*domainauth.Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*domainauth.Group, 0, len(s.groups))
	for _, g := range s.groups {
		cp := *g
		out = append(out, &cp)
	}
	_ = ctx
	return out
}

func (s *IdentityService) persistLocked(ctx context.Context) error {
	if s.repo == nil || s.crypto == nil {
		return nil
	}
	snap := identitySnapshot{}
	for _, e := range s.entities {
		snap.Entities = append(snap.Entities, cloneEntity(e))
	}
	for _, a := range s.aliases {
		cp := *a
		snap.Aliases = append(snap.Aliases, &cp)
	}
	for _, g := range s.groups {
		cp := *g
		snap.Groups = append(snap.Groups, &cp)
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	dataEnc, dekEnc, err := s.crypto.Seal(raw)
	if err != nil {
		return err
	}
	sv := &domainsecrets.SecretVersion{
		ID:        uuid.New(),
		Path:      identityBlobPath,
		DataEnc:   dataEnc,
		DEKEnc:    dekEnc,
		CreatedAt: time.Now().UTC(),
		Labels:    map[string]string{"engine": "identity"},
	}
	_, err = s.repo.PutAtomic(ctx, sv, nil, 5)
	return err
}

func (s *IdentityService) load(ctx context.Context) error {
	if s.repo == nil || s.crypto == nil {
		return nil
	}
	sv, err := s.repo.GetLatest(ctx, identityBlobPath)
	if err != nil {
		return nil // empty store
	}
	plain, err := s.crypto.Open(sv.DataEnc, sv.DEKEnc)
	if err != nil {
		return err
	}
	var snap identitySnapshot
	if err := json.Unmarshal(plain, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entities = make(map[string]*domainauth.Entity)
	s.aliases = make(map[string]*domainauth.Alias)
	s.byMount = make(map[string]string)
	s.groups = make(map[string]*domainauth.Group)
	for _, e := range snap.Entities {
		if e != nil {
			s.entities[e.ID] = e
		}
	}
	for _, a := range snap.Aliases {
		if a != nil {
			s.aliases[a.ID] = a
			s.byMount[a.Mount+"\x00"+a.Name] = a.ID
		}
	}
	for _, g := range snap.Groups {
		if g != nil {
			s.groups[g.ID] = g
		}
	}
	return nil
}

func cloneEntity(e *domainauth.Entity) *domainauth.Entity {
	if e == nil {
		return nil
	}
	cp := *e
	cp.Policies = append([]string(nil), e.Policies...)
	if e.Metadata != nil {
		cp.Metadata = map[string]string{}
		for k, v := range e.Metadata {
			cp.Metadata[k] = v
		}
	}
	return &cp
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
