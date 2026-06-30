package dragonboat_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/audit"
	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/raft"
	"github.com/kubenexis/knxvault/internal/repository/dragonboat"
)

type mockRaftClient struct {
	propose func(ctx context.Context, op string, payload any) ([]byte, error)
	read    func(ctx context.Context, op string, payload any) ([]byte, error)
}

func (m *mockRaftClient) Propose(ctx context.Context, op string, payload any) ([]byte, error) {
	if m.propose != nil {
		return m.propose(ctx, op, payload)
	}
	return nil, errors.New("propose not configured")
}

func (m *mockRaftClient) Read(ctx context.Context, op string, payload any) ([]byte, error) {
	if m.read != nil {
		return m.read(ctx, op, payload)
	}
	return nil, errors.New("read not configured")
}

func successResponse(data any) []byte {
	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	resp, err := json.Marshal(raft.Response{Data: b})
	if err != nil {
		panic(err)
	}
	return resp
}

func errorResponse(code, message string) []byte {
	resp, err := json.Marshal(raft.Response{ErrorCode: code, Message: message})
	if err != nil {
		panic(err)
	}
	return resp
}

func TestCARepositorySaveProposeError(t *testing.T) {
	client := &mockRaftClient{
		propose: func(context.Context, string, any) ([]byte, error) {
			return nil, errors.New("raft unavailable")
		},
	}
	repo := dragonboat.NewCARepository(client)
	err := repo.Save(context.Background(), &pki.CA{Name: "root"})
	if err == nil {
		t.Fatal("expected propose error")
	}
}

func TestCARepositoryGetByNameRead(t *testing.T) {
	ca := pki.CA{ID: uuid.New(), Name: "root"}
	client := &mockRaftClient{
		read: func(_ context.Context, op string, _ any) ([]byte, error) {
			if op != raft.OpCAGetByName {
				t.Fatalf("op = %q", op)
			}
			return successResponse(ca), nil
		},
	}
	repo := dragonboat.NewCARepository(client)
	got, err := repo.GetByName(context.Background(), "root")
	if err != nil {
		t.Fatalf("GetByName() = %v", err)
	}
	if got.Name != "root" {
		t.Fatalf("Name = %q", got.Name)
	}
}

func TestSecretRepositoryPutAtomic(t *testing.T) {
	client := &mockRaftClient{
		propose: func(_ context.Context, op string, _ any) ([]byte, error) {
			if op != raft.OpSecretPut {
				t.Fatalf("op = %q", op)
			}
			return successResponse(2), nil
		},
	}
	repo := dragonboat.NewSecretRepository(client)
	version, err := repo.PutAtomic(context.Background(), &secrets.SecretVersion{Path: "app"}, nil, 10)
	if err != nil {
		t.Fatalf("PutAtomic() = %v", err)
	}
	if version != 2 {
		t.Fatalf("version = %d, want 2", version)
	}
}

func TestLeaseRepositoryCountActive(t *testing.T) {
	client := &mockRaftClient{
		read: func(_ context.Context, op string, _ any) ([]byte, error) {
			if op != raft.OpLeaseCountActive {
				t.Fatalf("op = %q", op)
			}
			return successResponse(3), nil
		},
	}
	repo := dragonboat.NewLeaseRepository(client)
	count, err := repo.CountActive(context.Background())
	if err != nil {
		t.Fatalf("CountActive() = %v", err)
	}
	if count != 3 {
		t.Fatalf("count = %d, want 3", count)
	}
}

func TestAuditRepositoryAppendDecodeError(t *testing.T) {
	client := &mockRaftClient{
		propose: func(context.Context, string, any) ([]byte, error) {
			return errorResponse("validation_error", "bad entry"), nil
		},
	}
	repo := dragonboat.NewAuditRepository(client)
	err := repo.Append(context.Background(), &audit.Entry{Action: "test", Status: "success"})
	if err == nil {
		t.Fatal("expected domain error")
	}
}

func TestPKIRoleRepositoryList(t *testing.T) {
	roles := []*pki.Role{{Name: "web", CAName: "root"}}
	client := &mockRaftClient{
		read: func(_ context.Context, op string, _ any) ([]byte, error) {
			if op != raft.OpPKIRoleList {
				t.Fatalf("op = %q", op)
			}
			return successResponse(roles), nil
		},
	}
	repo := dragonboat.NewPKIRoleRepository(client)
	got, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(got) != 1 || got[0].Name != "web" {
		t.Fatalf("unexpected roles: %+v", got)
	}
	_ = time.Now()
}
