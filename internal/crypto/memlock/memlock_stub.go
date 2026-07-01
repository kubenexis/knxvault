//go:build !linux

package memlock

func platformMlock([]byte) error   { return nil }
func platformMunlock([]byte) error { return nil }
