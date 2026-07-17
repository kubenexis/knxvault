// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package sys

import "errors"

// ErrAlreadyInitialized indicates bootstrap was already performed.
var ErrAlreadyInitialized = errors.New("system already initialized")
