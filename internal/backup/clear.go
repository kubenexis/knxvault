package backup

import (
	"context"

	"github.com/kubenexis/knxvault/internal/repository/memory"
)

// ClearRepos wipes in-memory repositories before a full restore.
func ClearRepos(ctx context.Context, repos Repos) error {
	clear := func(c memory.Clearable) error {
		if c == nil {
			return nil
		}
		return c.Clear(ctx)
	}
	if err := clear(asClearable(repos.CA)); err != nil {
		return err
	}
	if err := clear(asClearable(repos.Secret)); err != nil {
		return err
	}
	if err := clear(asClearable(repos.Audit)); err != nil {
		return err
	}
	if err := clear(asClearable(repos.Revoke)); err != nil {
		return err
	}
	if err := clear(asClearable(repos.Lease)); err != nil {
		return err
	}
	if err := clear(asClearable(repos.Policy)); err != nil {
		return err
	}
	if err := clear(asClearable(repos.Role)); err != nil {
		return err
	}
	if err := clear(asClearable(repos.PKIRole)); err != nil {
		return err
	}
	if err := clear(asClearable(repos.DBRole)); err != nil {
		return err
	}
	if err := clear(asClearable(repos.SSHRole)); err != nil {
		return err
	}
	if err := clear(asClearable(repos.IssuedCert)); err != nil {
		return err
	}
	if err := clear(asClearable(repos.Token)); err != nil {
		return err
	}
	return nil
}

func asClearable(v any) memory.Clearable {
	if c, ok := v.(memory.Clearable); ok {
		return c
	}
	return nil
}
