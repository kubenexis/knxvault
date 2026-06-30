// Package common provides shared domain primitives.
package common

import "fmt"

// ErrorCode identifies a KNXVault API error category.
type ErrorCode string

const (
	ErrCodeInternal     ErrorCode = "internal_error"
	ErrCodeValidation   ErrorCode = "validation_error"
	ErrCodeUnauthorized ErrorCode = "unauthorized"
	ErrCodeForbidden    ErrorCode = "forbidden"
	ErrCodeNotFound     ErrorCode = "not_found"
)

// KNXVaultError is a typed application error with an API-safe code.
type KNXVaultError struct {
	Code    ErrorCode
	Message string
	Cause   error
}

func (e *KNXVaultError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *KNXVaultError) Unwrap() error {
	return e.Cause
}

// New creates a KNXVaultError.
func New(code ErrorCode, message string) *KNXVaultError {
	return &KNXVaultError{Code: code, Message: message}
}

// Wrap creates a KNXVaultError wrapping cause.
func Wrap(code ErrorCode, message string, cause error) *KNXVaultError {
	return &KNXVaultError{Code: code, Message: message, Cause: cause}
}
