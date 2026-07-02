package dto

// LockoutClearRequest clears a login lockout (W43-04).
type LockoutClearRequest struct {
	AuthMethod string `json:"auth_method" binding:"required"`
	SourceIP   string `json:"source_ip" binding:"required"`
}