package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

// IdentityService manages entities, aliases, and groups (M-IDENT-1).
type IdentityService struct {
	mu       sync.RWMutex
	entities map[string]*domainauth.Entity
	aliases  map[string]*domainauth.Alias // id
	byMount  map[string]string            // mount\x00name -> alias id
	groups   map[string]*domainauth.Group
	audit    *auditsvc.Service
}

// NewIdentityService constructs an in-memory identity service.
func NewIdentityService(audit *auditsvc.Service) *IdentityService {
	return &IdentityService{
		entities: make(map[string]*domainauth.Entity),
		aliases:  make(map[string]*domainauth.Alias),
		byMount:  make(map[string]string),
		groups:   make(map[string]*domainauth.Group),
		audit:    audit,
	}
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
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
	s.mu.Unlock()
	audithelper.Record(s.audit, ctx, "identity.entity.create", "identity/entity/"+e.ID, nil, map[string]any{"name": name})
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
	audithelper.Record(s.audit, ctx, "identity.entity.disable", "identity/entity/"+id, nil, map[string]any{"disabled": disabled})
	return nil
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
	audithelper.Record(s.audit, ctx, "identity.alias.create", "identity/alias/"+a.ID, nil, map[string]any{"mount": mount})
	cp := *a
	return &cp, nil
}

// CreateGroup creates a group.
func (s *IdentityService) CreateGroup(ctx context.Context, name string, members, policies []string) (*domainauth.Group, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, common.New(common.ErrCodeValidation, "name required")
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
	s.mu.Unlock()
	audithelper.Record(s.audit, ctx, "identity.group.create", "identity/group/"+g.ID, nil, map[string]any{"name": name})
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
