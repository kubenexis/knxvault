package sys

import "errors"

// ErrAlreadyInitialized indicates bootstrap was already performed.
var ErrAlreadyInitialized = errors.New("system already initialized")