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

// minimalRedis implements basic GET/SET/DEL over RESP (W33-01).
type minimalRedis struct {
	addr string
}

func newMinimalRedis(url string) (*minimalRedis, error) {
	addr := strings.TrimPrefix(url, "redis://")
	if addr == "" {
		return nil, fmt.Errorf("invalid redis url")
	}
	return &minimalRedis{addr: addr}, nil
}

func (r *minimalRedis) Get(ctx context.Context, key string) ([]byte, bool) {
	conn, err := r.dial(ctx)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	if err := writeCommand(conn, "GET", key); err != nil {
		return nil, false
	}
	return readBulkString(bufio.NewReader(conn))
}

func (r *minimalRedis) Set(ctx context.Context, key string, value []byte, ttl time.Duration) {
	conn, err := r.dial(ctx)
	if err != nil {
		return
	}
	defer conn.Close()
	if ttl > 0 {
		_ = writeCommand(conn, "SET", key, string(value), "EX", fmt.Sprintf("%d", int(ttl.Seconds())))
		return
	}
	_ = writeCommand(conn, "SET", key, string(value))
}

func (r *minimalRedis) Delete(ctx context.Context, key string) {
	conn, err := r.dial(ctx)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = writeCommand(conn, "DEL", key)
}

func (r *minimalRedis) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	return d.DialContext(ctx, "tcp", r.addr)
}

func writeCommand(w io.Writer, parts ...string) error {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("*%d\r\n", len(parts)))
	for _, p := range parts {
		b.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(p), p))
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
	fmt.Sscanf(strings.TrimSpace(line), "$%d", &n)
	if n <= 0 {
		return nil, false
	}
	buf := make([]byte, n+2)
	if _, err := r.Read(buf); err != nil {
		return nil, false
	}
	return buf[:n], true
}
