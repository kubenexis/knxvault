package auth

import "time"

// ClientToken is a persisted opaque client token record.
// Only the SHA-256 hash of the raw token is stored; the raw value is returned once at issuance.
type ClientToken struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject"`
	Policies  []string  `json:"policies"`
	ExpiresAt time.Time `json:"expires_at"`
	Renewable bool      `json:"renewable"`
	Revoked   bool      `json:"revoked"`
}

// Active reports whether the token is valid at the given time.
func (t ClientToken) Active(now time.Time) bool {
	return !t.Revoked && now.Before(t.ExpiresAt)
}
