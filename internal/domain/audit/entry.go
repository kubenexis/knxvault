package audit

import (
	"fmt"
	"time"
)

// Entry is an append-only audit log record (LLD §4.D.1).
type Entry struct {
	ID        int64
	Timestamp time.Time
	Actor     string
	Action    string
	Resource  string
	Status    string
	Details   map[string]any
	Hash      string
	Signature string
}

// Validate checks required audit fields.
func (e *Entry) Validate() error {
	if e.Action == "" {
		return fmt.Errorf("audit action is required")
	}
	if e.Status == "" {
		return fmt.Errorf("audit status is required")
	}
	return nil
}