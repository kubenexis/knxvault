//go:build linux

package memlock

import (
	"fmt"
	"syscall"
)

func platformMlock(b []byte) error {
	if err := syscall.Mlock(b); err != nil {
		return fmt.Errorf("mlock: %w", err)
	}
	return nil
}

func platformMunlock(b []byte) error {
	if err := syscall.Munlock(b); err != nil {
		return fmt.Errorf("munlock: %w", err)
	}
	return nil
}
