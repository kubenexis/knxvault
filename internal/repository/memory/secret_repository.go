package memory

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

type secretKey struct {
	path    string
	version int
}

// SecretRepository is an in-memory secret version store.
type SecretRepository struct {
	mu       sync.RWMutex
	versions map[secretKey]*secrets.SecretVersion
}

// NewSecretRepository constructs an empty SecretRepository.
func NewSecretRepository() *SecretRepository {
	return &SecretRepository{versions: make(map[secretKey]*secrets.SecretVersion)}
}

// SaveVersion stores a secret version.
func (r *SecretRepository) SaveVersion(_ context.Context, sv *secrets.SecretVersion) error {
	if err := sv.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid secret version", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	key := secretKey{path: sv.Path, version: sv.Version}
	if _, exists := r.versions[key]; exists {
		return common.New(common.ErrCodeValidation, "secret version already exists")
	}

	stored := *sv
	r.versions[key] = &stored
	return nil
}

// GetLatest returns the newest non-destroyed version.
func (r *SecretRepository) GetLatest(_ context.Context, path string) (*secrets.SecretVersion, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var latest *secrets.SecretVersion
	for key, sv := range r.versions {
		if key.path != path || sv.Destroyed {
			continue
		}
		if latest == nil || sv.Version > latest.Version {
			stored := *sv
			latest = &stored
		}
	}
	if latest == nil {
		return nil, common.New(common.ErrCodeNotFound, "secret version not found")
	}
	return latest, nil
}

// GetVersion returns a specific version.
func (r *SecretRepository) GetVersion(_ context.Context, path string, version int) (*secrets.SecretVersion, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sv, ok := r.versions[secretKey{path: path, version: version}]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "secret version not found")
	}
	stored := *sv
	return &stored, nil
}

// ListByPath returns versions with matching path prefix.
func (r *SecretRepository) ListByPath(_ context.Context, pathPrefix string) ([]*secrets.SecretVersion, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []*secrets.SecretVersion
	for _, sv := range r.versions {
		if strings.HasPrefix(sv.Path, pathPrefix) {
			stored := *sv
			out = append(out, &stored)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Version < out[j].Version
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

// NextVersion returns the next version number for path.
func (r *SecretRepository) NextVersion(_ context.Context, path string) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	max := 0
	for key := range r.versions {
		if key.path == path && key.version > max {
			max = key.version
		}
	}
	return max + 1, nil
}
