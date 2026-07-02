package cache

import "testing"

func TestParseValkeyURLSchemes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		url    string
		want   string
		wantOK bool
	}{
		{"valkey://10.0.0.1:6379", "10.0.0.1:6379", true},
		{"redis://10.0.0.1:6379", "10.0.0.1:6379", true},
		{"10.0.0.1:6379", "10.0.0.1:6379", true},
		{"", "", false},
		{"valkey://", "", false},
	}
	for _, tt := range tests {
		addr, err := parseValkeyURL(tt.url)
		if tt.wantOK && err != nil {
			t.Fatalf("parseValkeyURL(%q) = %v", tt.url, err)
		}
		if !tt.wantOK && err == nil {
			t.Fatalf("parseValkeyURL(%q) expected error", tt.url)
		}
		if tt.wantOK && addr != tt.want {
			t.Fatalf("parseValkeyURL(%q) = %q, want %q", tt.url, addr, tt.want)
		}
	}
}
