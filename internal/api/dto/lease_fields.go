package dto

import "time"

// LeaseFields are common lease metadata on creds responses (W42-05).
type LeaseFields struct {
	LeaseID       string    `json:"lease_id"`
	LeaseDuration int       `json:"lease_duration"`
	LeaseMaxTTL   int       `json:"lease_max_ttl"`
	ExpiresAt     time.Time `json:"expires_at"`
	Warnings      []string  `json:"warnings,omitempty"`
}
