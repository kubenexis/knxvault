// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

// KVSecretReader adapts SecretsService to inject.SecretReader.
type KVSecretReader struct {
	svc *SecretsService
}

// NewKVSecretReader constructs a KV-backed secret reader.
func NewKVSecretReader(svc *SecretsService) *KVSecretReader {
	return &KVSecretReader{svc: svc}
}

// ReadSecret fetches the latest KV secret data.
func (r *KVSecretReader) ReadSecret(ctx context.Context, path string) (map[string]any, error) {
	if r.svc == nil {
		return nil, common.New(common.ErrCodeInternal, "secrets service not configured")
	}
	result, err := r.svc.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}
