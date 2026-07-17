// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package inject renders secrets for sidecar, init-container, and CSI injection (W18).
package inject

import (
	"context"
	"fmt"
	"path"
	"strings"
)

// Format selects how secrets are materialized in a pod.
type Format string

const (
	FormatFiles Format = "files"
	FormatEnv   Format = "env"
	FormatBoth  Format = "both"
)

// SecretRef references a KV secret path to inject.
type SecretRef struct {
	Path     string `json:"path"`
	FileName string `json:"file_name,omitempty"`
	EnvName  string `json:"env_name,omitempty"`
}

// RenderRequest configures secret injection output.
type RenderRequest struct {
	Secrets []SecretRef `json:"secrets"`
	Format  Format      `json:"format"`
}

// FileEntry is a file to write in a sidecar/init volume.
type FileEntry struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode"`
}

// EnvEntry is an environment variable injection.
type EnvEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RenderResult contains materialized secret payloads.
type RenderResult struct {
	Files []FileEntry `json:"files,omitempty"`
	Env   []EnvEntry  `json:"env,omitempty"`
}

// SecretReader fetches secret data by path.
type SecretReader interface {
	ReadSecret(ctx context.Context, secretPath string) (map[string]any, error)
}

// Renderer materializes secrets for injection patterns.
type Renderer struct {
	reader SecretReader
}

// NewRenderer constructs a secret injection renderer.
func NewRenderer(reader SecretReader) *Renderer {
	return &Renderer{reader: reader}
}

// Render fetches secrets and formats them for injection.
func (r *Renderer) Render(ctx context.Context, req RenderRequest) (*RenderResult, error) {
	if r.reader == nil {
		return nil, fmt.Errorf("secret reader not configured")
	}
	if len(req.Secrets) == 0 {
		return nil, fmt.Errorf("at least one secret reference is required")
	}
	format := req.Format
	if format == "" {
		format = FormatBoth
	}

	result := &RenderResult{}
	for _, ref := range req.Secrets {
		if ref.Path == "" {
			return nil, fmt.Errorf("secret path is required")
		}
		data, err := r.reader.ReadSecret(ctx, ref.Path)
		if err != nil {
			return nil, err
		}
		if format == FormatFiles || format == FormatBoth {
			fileName := ref.FileName
			if fileName == "" {
				fileName = sanitizeFileName(ref.Path)
			}
			result.Files = append(result.Files, FileEntry{
				Path:    path.Join("/vault/secrets", fileName),
				Content: flattenSecret(data),
				Mode:    "0400",
			})
		}
		if format == FormatEnv || format == FormatBoth {
			for key, value := range data {
				envName := ref.EnvName
				if envName == "" {
					envName = sanitizeEnvName(ref.Path + "_" + key)
				} else if len(data) == 1 {
					// single-key secret uses explicit env name
				} else {
					envName = sanitizeEnvName(envName + "_" + key)
				}
				result.Env = append(result.Env, EnvEntry{
					Name:  envName,
					Value: fmt.Sprint(value),
				})
			}
		}
	}
	return result, nil
}

func flattenSecret(data map[string]any) string {
	if len(data) == 0 {
		return ""
	}
	if len(data) == 1 {
		for _, v := range data {
			return fmt.Sprint(v)
		}
	}
	var b strings.Builder
	first := true
	for k, v := range data {
		if !first {
			b.WriteByte('\n')
		}
		first = false
		b.WriteString(k)
		b.WriteString("=")
		_, _ = fmt.Fprint(&b, v)
	}
	return b.String()
}

func sanitizeFileName(p string) string {
	p = strings.TrimPrefix(p, "/")
	p = strings.ReplaceAll(p, "/", "_")
	if p == "" {
		return "secret"
	}
	return p
}

func sanitizeEnvName(raw string) string {
	raw = strings.ToUpper(raw)
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "SECRET"
	}
	return out
}
