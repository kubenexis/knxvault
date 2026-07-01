// Package tlsconfig loads TLS certificate material for servers and clients.
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// ServerConfig holds HTTP listener TLS settings.
type ServerConfig struct {
	CertFile     string
	KeyFile      string
	MTLSRequired bool
	CAFile       string
}

// LoadServerTLS builds a tls.Config for the HTTP server.
func LoadServerTLS(cfg ServerConfig) (*tls.Config, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if cfg.MTLSRequired {
		if cfg.CAFile == "" {
			return nil, fmt.Errorf("mTLS CA file required when mTLS is enabled")
		}
		pool, err := loadCAPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg, nil
}

func loadCAPool(caFile string) (*x509.CertPool, error) {
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("parse CA PEM")
	}
	return pool, nil
}

// ValidateMTLSFiles ensures all three Raft mTLS paths are set together.
func ValidateMTLSFiles(cert, key, ca string) error {
	set := cert != "" || key != "" || ca != ""
	if !set {
		return nil
	}
	if cert == "" || key == "" || ca == "" {
		return fmt.Errorf("raft mTLS requires cert, key, and CA paths")
	}
	return nil
}
