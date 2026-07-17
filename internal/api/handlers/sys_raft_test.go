// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
)

type mockRaftMembership struct {
	leader    bool
	addErr    error
	removeErr error
	added     uint64
	removed   uint64
}

func (m *mockRaftMembership) AddNode(_ context.Context, nodeID uint64, _ string) error {
	m.added = nodeID
	return m.addErr
}

func (m *mockRaftMembership) RemoveNode(_ context.Context, nodeID uint64) error {
	m.removed = nodeID
	return m.removeErr
}

func (m *mockRaftMembership) IsLeader() bool { return m.leader }

func TestSysHandlerRaftAddNodeRequiresLeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := testAuthService("admin")
	raft := &mockRaftMembership{leader: false}
	handler := handlers.NewSysHandler(authSvc, nil, nil, nil, nil, nil, nil, raft, nil, false, nil)

	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.POST("/sys/raft/add-node", handler.RaftAddNode)

	body, _ := json.Marshal(map[string]any{"node_id": 2, "address": "host:63001"})
	req := httptest.NewRequest(http.MethodPost, "/sys/raft/add-node", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestSysHandlerRaftAddNodeOnLeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := testAuthService("admin")
	raft := &mockRaftMembership{leader: true}
	handler := handlers.NewSysHandler(authSvc, nil, nil, nil, nil, nil, nil, raft, nil, false, nil)

	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.POST("/sys/raft/add-node", handler.RaftAddNode)

	body, _ := json.Marshal(map[string]any{"node_id": 2, "address": "host:63001"})
	req := httptest.NewRequest(http.MethodPost, "/sys/raft/add-node", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if raft.added != 2 {
		t.Fatalf("added node = %d, want 2", raft.added)
	}
}

func TestSysHandlerRaftRemoveNodeRequiresLeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := testAuthService("admin")
	raft := &mockRaftMembership{leader: false}
	handler := handlers.NewSysHandler(authSvc, nil, nil, nil, nil, nil, nil, raft, nil, false, nil)

	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.POST("/sys/raft/remove-node", handler.RaftRemoveNode)

	body, _ := json.Marshal(map[string]any{"node_id": 3})
	req := httptest.NewRequest(http.MethodPost, "/sys/raft/remove-node", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestSysHandlerRaftMembershipNotConfigured(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := testAuthService("admin")
	handler := handlers.NewSysHandler(authSvc, nil, nil, nil, nil, nil, nil, nil, nil, false, nil)

	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.POST("/sys/raft/add-node", handler.RaftAddNode)

	body, _ := json.Marshal(map[string]any{"node_id": 2, "address": "host:63001"})
	req := httptest.NewRequest(http.MethodPost, "/sys/raft/add-node", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}
