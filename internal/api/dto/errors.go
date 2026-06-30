package dto

import "time"

// ErrorResponse is the standard API error envelope (LLD §5.3).
type ErrorResponse struct {
	ErrorCode string    `json:"error_code"`
	Message   string    `json:"message"`
	Details   any       `json:"details,omitempty"`
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
}
