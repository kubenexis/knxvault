package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestDelegateAgentScopesPathAndActions(t *testing.T) {
	store := auth.NewTokenStore(time.Hour)
	rbac := auth.NewRBAC()
	svc := auth.NewService(store, rbac, "")
	parent := auth.Principal{
		Subject:  "ci-bot",
		Policies: []string{"secrets-admin"},
	}
	token, record, err := svc.DelegateAgent(context.Background(), parent, auth.AgentDelegateRequest{
		AgentID:        "planner-1",
		PathPrefix:     "agent/planner-1",
		AllowedActions: []string{"read"},
	})
	if err != nil {
		t.Fatalf("DelegateAgent() = %v", err)
	}
	if token == "" || record.AgentID != "planner-1" {
		t.Fatalf("unexpected record: %+v", record)
	}
	if record.ParentIdentityID != "ci-bot" {
		t.Fatalf("parent = %q", record.ParentIdentityID)
	}
	if record.Renewable {
		t.Fatal("agent tokens must not be renewable")
	}
	if record.PathPrefix != "agent/planner-1/" {
		t.Fatalf("path prefix = %q", record.PathPrefix)
	}

	agentPrincipal := auth.Principal{
		Subject:        record.Subject,
		Policies:       record.Policies,
		AgentID:        record.AgentID,
		AllowedActions: record.AllowedActions,
		PathPrefix:     record.PathPrefix,
	}
	if err := svc.Authorize(context.Background(), agentPrincipal, "secrets/kv/agent/planner-1/config", "read"); err != nil {
		t.Fatalf("authorize in-prefix read: %v", err)
	}
	if err := svc.Authorize(context.Background(), agentPrincipal, "secrets/kv/other/config", "read"); err == nil {
		t.Fatal("expected path outside prefix to be denied")
	}
	if err := svc.Authorize(context.Background(), agentPrincipal, "secrets/kv/agent/planner-1/config", "write"); err == nil {
		t.Fatal("expected write outside allowed_actions to be denied")
	}
}

func TestConditionsMatchAgentID(t *testing.T) {
	policy := domainauth.Policy{
		Name:      "agent-only",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"secrets/kv/*"},
		Actions:   []string{"read"},
		Conditions: map[string]any{
			"agent_id": "planner-1",
		},
	}
	if !auth.PolicyMatches(policy, "secrets/kv/agent/planner-1/x", "read", auth.RequestContext{AgentID: "planner-1"}) {
		t.Fatal("expected agent_id condition to match")
	}
	if auth.PolicyMatches(policy, "secrets/kv/agent/planner-1/x", "read", auth.RequestContext{AgentID: "other"}) {
		t.Fatal("expected agent_id condition to fail")
	}
}
