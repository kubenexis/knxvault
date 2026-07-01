package pki

import (
	"fmt"
	"os"
	"path/filepath"
)

type workspace struct {
	dir string
}

func newWorkspace() (*workspace, error) {
	dir, err := os.MkdirTemp("", "knxvault-pki-*")
	if err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("chmod workspace: %w", err)
	}
	return &workspace{dir: dir}, nil
}

func (w *workspace) path(name string) string {
	return filepath.Join(w.dir, name)
}

func (w *workspace) write(name string, content []byte) error {
	if err := os.WriteFile(w.path(name), content, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

func (w *workspace) read(name string) ([]byte, error) {
	data, err := os.ReadFile(w.path(name))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return data, nil
}

func (w *workspace) cleanup() {
	_ = os.RemoveAll(w.dir)
}
