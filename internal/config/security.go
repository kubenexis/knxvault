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
		if cfg.UnsealKey == "" {
			return fmt.Errorf("unseal key is required when raft is enabled (set KNXVAULT_UNSEAL_KEY)")
		}
		if configPath != "" && (cfg.RootToken != "" || cfg.JWTSecret != "") {
			return fmt.Errorf("root_token and jwt_secret must be supplied via environment when raft is enabled, not config file")
		}
		// W50-20: multi-node Raft requires peer mTLS unless explicitly allowed (dev/lab).
		if !cfg.RaftAllowInsecure && len(cfg.Raft.InitialMembers) > 1 {
			if cfg.Raft.MTLSCertFile == "" || cfg.Raft.MTLSKeyFile == "" || cfg.Raft.MTLSCAFile == "" {
				return fmt.Errorf("raft mTLS (KNXVAULT_RAFT_MTLS_CERT/KEY/CA) is required for multi-node raft; set KNXVAULT_RAFT_ALLOW_INSECURE=true only for lab")
			}
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
