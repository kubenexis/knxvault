// Package memlock locks sensitive memory pages to reduce swap exposure.
package memlock

import (
	"fmt"
	"runtime"
)

// Lock prevents the byte slice's underlying pages from being swapped out.
// On unsupported platforms this is a no-op.
func Lock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return platformMlock(b)
}

// Unlock releases a prior mlock on b.
func Unlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return platformMunlock(b)
}

// Locked copies src into a new mlocked buffer.
func Locked(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("cannot lock empty buffer")
	}
	out := make([]byte, len(src))
	copy(out, src)
	if err := Lock(out); err != nil {
		return nil, err
	}
	runtime.KeepAlive(out)
	return out, nil
}
