package acme

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// ListenHTTP01 serves MemoryHTTP01 on addr (e.g. ":80" or "127.0.0.1:8082").
// Caller must Close the returned server when done.
func ListenHTTP01(addr string, m *MemoryHTTP01) (*http.Server, net.Listener, error) {
	if m == nil {
		return nil, nil, fmt.Errorf("http-01 memory presenter is nil")
	}
	if addr == "" {
		addr = ":80"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("http-01 listen %s: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           m,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return srv, ln, nil
}
