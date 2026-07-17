// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package api

import "context"

// ReadinessChecker reports whether the application is ready to serve traffic.
type ReadinessChecker interface {
	Ready(ctx context.Context) error
}
