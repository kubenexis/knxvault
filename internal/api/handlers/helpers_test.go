// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func testCryptoKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func testCryptoService() (*crypto.Service, error) {
	return crypto.NewService(testCryptoKey())
}

func testAuthService(policies ...string) *auth.Service {
	tokenStore := auth.NewTokenStore(time.Hour)
	_ = tokenStore.RegisterRootToken(context.Background(), "root-token", policies)
	return auth.NewService(tokenStore, auth.NewRBAC(), "")
}

func testAuditService() *auditsvc.Service {
	return auditsvc.NewService(memory.NewAuditRepository())
}
