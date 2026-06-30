package utils_test

import (
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/utils"
)

func TestParseTTL(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"8760h", 8760 * time.Hour},
		{"365d", 365 * 24 * time.Hour},
		{"30m", 30 * time.Minute},
		{"90s", 90 * time.Second},
	}

	for _, tc := range tests {
		got, err := utils.ParseTTL(tc.in)
		if err != nil {
			t.Fatalf("ParseTTL(%q) err = %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseTTL(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
