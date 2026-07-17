// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/kubenexis/knxvault/internal/acme/filestore"
)

// RunIssue loads account key, issues, writes files, updates state, runs hook.
func RunIssue(ctx context.Context, p *Profile) (*Result, error) {
	if p == nil {
		return nil, fmt.Errorf("profile is nil")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	acct := AccountKeyFile{Path: resolvePath(p.AccountKey)}
	key, err := acct.LoadOrCreate()
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	http01, dns01, mem, err := BuildSolversFromProfile(p)
	if err != nil {
		return nil, err
	}
	var stop func()
	if mem != nil && p.HTTP01 != nil {
		addr := p.HTTP01.ListenAddr
		if addr == "" {
			addr = ":80"
		}
		srv, _, err := ListenHTTP01(addr, mem)
		if err != nil {
			return nil, err
		}
		stop = func() { _ = srv.Close() }
		defer stop()
	}
	cfg := p.ToConfig(key)
	client := NewClient(cfg, http01, dns01)
	res, err := client.Issue(ctx, p.PrimaryOrder())
	if err != nil {
		return nil, err
	}
	chain := res.ChainPEM
	if chain == "" {
		chain = res.CertPEM
		if res.IssuerPEM != "" {
			chain = res.CertPEM + res.IssuerPEM
		}
	}
	if err := filestore.WritePEMFiles(p.Delivery.CertPath, p.Delivery.KeyPath, chain, res.PrivateKeyPEM); err != nil {
		return nil, err
	}
	statePath := p.StateFile
	if statePath == "" {
		statePath = p.Delivery.CertPath + ".acme-state.json"
	}
	rec := &filestore.CertRecord{
		Profile:      p.Name,
		CommonName:   p.Domains[0].Name,
		DNSNames:     p.PrimaryOrder().DNSNames,
		DirectoryURL: p.DirectoryURL,
		CertPath:     p.Delivery.CertPath,
		KeyPath:      p.Delivery.KeyPath,
		Serial:       res.Serial,
		NotBefore:    res.NotBefore,
		NotAfter:     res.NotAfter,
	}
	if err := (filestore.CertStateFile{Path: statePath}).Save(rec); err != nil {
		return nil, err
	}
	if err := runHook(p.PostRenewHook); err != nil {
		return res, fmt.Errorf("issued but hook failed: %w", err)
	}
	return res, nil
}

// RunRenew renews if needed using state file + profile.
func RunRenew(ctx context.Context, p *Profile) (renewed bool, res *Result, err error) {
	if p == nil {
		return false, nil, fmt.Errorf("profile is nil")
	}
	statePath := p.StateFile
	if statePath == "" {
		statePath = p.Delivery.CertPath + ".acme-state.json"
	}
	rec, err := (filestore.CertStateFile{Path: statePath}).Load()
	if err != nil {
		return false, nil, err
	}
	now := time.Now().UTC()
	if !NeedsRenew(rec, now, RenewPolicy{RenewBefore: p.RenewBeforeDuration()}) {
		return false, nil, nil
	}
	res, err = RunIssue(ctx, p)
	if err != nil {
		return false, nil, err
	}
	return true, res, nil
}

// DoctorProfile returns human-readable checks for a profile.
func DoctorProfile(p *Profile) []string {
	var out []string
	if p == nil {
		return []string{"profile is nil"}
	}
	if err := p.Validate(); err != nil {
		out = append(out, "validate: "+err.Error())
	} else {
		out = append(out, "profile: ok")
	}
	if p.AccountKey != "" {
		path := resolvePath(p.AccountKey)
		if st, err := os.Stat(path); err != nil {
			out = append(out, "account_key: missing (will create on issue)")
		} else if st.Mode().Perm()&0o077 != 0 {
			out = append(out, "account_key: permissions too open (want 0600)")
		} else {
			out = append(out, "account_key: present")
		}
	}
	if p.SkipTLSVerify {
		out = append(out, "warn: skip_tls_verify is set (lab only)")
	}
	if PublicLEHost(p.DirectoryURL) {
		out = append(out, "directory: public Let's Encrypt host")
	}
	return out
}

func runHook(hook string) error {
	hook = filepath.Clean(hook)
	if hook == "" || hook == "." {
		return nil
	}
	// Only absolute or PATH commands — invoke via shell-less exec.
	cmd := exec.Command(hook)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func resolvePath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	// Relative to cwd for CLI convenience.
	return p
}
