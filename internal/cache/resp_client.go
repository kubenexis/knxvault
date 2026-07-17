// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// respClient implements GET/SET/DEL over the Valkey RESP wire protocol.
type respClient struct {
	addr string
}

func parseValkeyURL(url string) (string, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return "", fmt.Errorf("valkey cache url is required")
	}
	// valkey:// is preferred; redis:// accepted as a legacy URL alias during migration.
	for _, prefix := range []string{"valkey://", "redis://"} {
		if strings.HasPrefix(url, prefix) {
			addr := strings.TrimPrefix(url, prefix)
			if addr == "" {
				return "", fmt.Errorf("invalid valkey cache url")
			}
			return addr, nil
		}
	}
	return url, nil
}

func newRESPClient(url string) (*respClient, error) {
	addr, err := parseValkeyURL(url)
	if err != nil {
		return nil, err
	}
	return &respClient{addr: addr}, nil
}

func (c *respClient) Get(ctx context.Context, key string) ([]byte, bool) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, false
	}
	defer func() { _ = conn.Close() }()
	if err := writeCommand(conn, "GET", key); err != nil {
		return nil, false
	}
	return readBulkString(bufio.NewReader(conn))
}

func (c *respClient) Set(ctx context.Context, key string, value []byte, ttl time.Duration) {
	conn, err := c.dial(ctx)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	if ttl > 0 {
		_ = writeCommand(conn, "SET", key, string(value), "EX", fmt.Sprintf("%d", int(ttl.Seconds())))
		return
	}
	_ = writeCommand(conn, "SET", key, string(value))
}

func (c *respClient) Delete(ctx context.Context, key string) {
	conn, err := c.dial(ctx)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = writeCommand(conn, "DEL", key)
}

func (c *respClient) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	return d.DialContext(ctx, "tcp", c.addr)
}

func writeCommand(w io.Writer, parts ...string) error {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "*%d\r\n", len(parts))
	for _, p := range parts {
		_, _ = fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(p), p)
	}
	_, err := w.Write([]byte(b.String()))
	return err
}

func readBulkString(r *bufio.Reader) ([]byte, bool) {
	line, err := r.ReadString('\n')
	if err != nil || strings.HasPrefix(line, "$-1") {
		return nil, false
	}
	if !strings.HasPrefix(line, "$") {
		return nil, false
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "$%d", &n); err != nil {
		return nil, false
	}
	if n <= 0 {
		return nil, false
	}
	buf := make([]byte, n+2)
	if _, err := r.Read(buf); err != nil {
		return nil, false
	}
	return buf[:n], true
}
