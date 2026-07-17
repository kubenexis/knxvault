// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/tenant"
)

// scopeResourceName prefixes names (roles, CAs, etc.) when tenant mode is on (W32-04 / W53).
func scopeResourceName(ctx context.Context, tenantMode bool, name string) (string, error) {
	if !tenantMode {
		return name, nil
	}
	ns := tenant.FromContext(ctx)
	if ns == "" {
		return "", common.New(common.ErrCodeValidation, "tenant namespace required")
	}
	return tenant.ScopePath(ns, name, true), nil
}

func assertTenantAccess(ctx context.Context, tenantMode bool, scopedName string) error {
	if !tenantMode {
		return nil
	}
	ns := tenant.FromContext(ctx)
	if ns == "" {
		return common.New(common.ErrCodeValidation, "tenant namespace required")
	}
	if !tenant.ValidateAccess(ns, scopedName, true) {
		return common.New(common.ErrCodeNotFound, "resource not found")
	}
	return nil
}
