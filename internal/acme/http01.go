package acme

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// MemoryHTTP01 is an in-memory HTTP-01 presenter and http.Handler for
// /.well-known/acme-challenge/<token>. Suitable for operator-embedded solvers
// and unit tests.
type MemoryHTTP01 struct {
	mu   sync.RWMutex
	auth map[string]string // token → keyAuth
}

// NewMemoryHTTP01 constructs an empty challenge store.
func NewMemoryHTTP01() *MemoryHTTP01 {
	return &MemoryHTTP01{auth: make(map[string]string)}
}

// Present stores the challenge response.
func (m *MemoryHTTP01) Present(_ context.Context, _, token, keyAuth string) error {
	if err := validateHTTP01Token(token); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.auth == nil {
		m.auth = make(map[string]string)
	}
	m.auth[token] = keyAuth
	return nil
}

// CleanUp removes the challenge response.
func (m *MemoryHTTP01) CleanUp(_ context.Context, _, token, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.auth, token)
	return nil
}

// Get returns keyAuth for token if present.
func (m *MemoryHTTP01) Get(token string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.auth[token]
	return v, ok
}

// ServeHTTP handles ACME HTTP-01 paths.
func (m *MemoryHTTP01) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	token = strings.Trim(token, "/")
	if token == "" || validateHTTP01Token(token) != nil {
		http.NotFound(w, r)
		return
	}
	keyAuth, ok := m.Get(token)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(keyAuth))
}

func validateHTTP01Token(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("http-01 token required")
	}
	// Tokens must be a single path segment (ACME base64url-ish).
	if strings.ContainsAny(token, "/\\") || strings.Contains(token, "..") {
		return fmt.Errorf("http-01 token must not contain path separators")
	}
	if len(token) > 256 {
		return fmt.Errorf("http-01 token too long")
	}
	return nil
}
