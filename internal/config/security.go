package config

import (
	"fmt"
	"os"
)

// ValidateSecurity enforces production-safe configuration constraints.
func ValidateSecurity(cfg Config, configPath string) error {
	if cfg.Raft.Enabled {
		if cfg.K8sAuthInsecure {
			return fmt.Errorf("k8s_auth_insecure is not allowed when raft is enabled")
		}
		if cfg.UnsealKey == "" && !cfg.Seal.ShamirEnabled() && !cfg.Seal.AutoUnsealEnabled() {
			return fmt.Errorf("unseal key, shamir scheme, or auto-unseal is required when raft is enabled")
		}
		if configPath != "" && (cfg.RootToken != "" || cfg.JWTSecret != "") {
			return fmt.Errorf("root_token and jwt_secret must be supplied via environment when raft is enabled, not config file")
		}
	}
	if configPath != "" {
		if err := checkConfigFilePermissions(configPath); err != nil {
			return err
		}
	}
	switch cfg.PKIBackend {
	case "", "openssl", "native":
	default:
		return fmt.Errorf("invalid pki_backend %q: must be openssl or native", cfg.PKIBackend)
	}
	return nil
}

func checkConfigFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config %s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("config file %s is group- or world-readable; restrict permissions to 0600", path)
	}
	return nil
}
