// Package sensitive provides mlocked buffers that are zeroed on release.
package sensitive

import (
	"github.com/kubenexis/knxvault/internal/crypto/memlock"
	"github.com/kubenexis/knxvault/internal/crypto/memzero"
)

// Buffer holds secret bytes with optional mlock and mandatory zero on Close.
type Buffer struct {
	b []byte
}

// New wraps a copy of src with mlock when possible.
func New(src []byte) (*Buffer, error) {
	locked, err := memlock.Locked(src)
	if err != nil {
		copy := append([]byte(nil), src...)
		return &Buffer{b: copy}, nil
	}
	return &Buffer{b: locked}, nil
}

// Bytes returns the underlying slice. Callers must not retain after Close.
func (s *Buffer) Bytes() []byte {
	if s == nil {
		return nil
	}
	return s.b
}

// Close zeros and unlocks the buffer.
func (s *Buffer) Close() {
	if s == nil || len(s.b) == 0 {
		return
	}
	memzero.Bytes(s.b)
	_ = memlock.Unlock(s.b)
	s.b = nil
}
