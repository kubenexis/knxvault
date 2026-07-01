package main

import "testing"

func TestLocalHealthPort(t *testing.T) {
	tests := []struct {
		addr    string
		want    string
		wantErr bool
	}{
		{addr: ":8200", want: "8200"},
		{addr: "0.0.0.0:8200", want: "8200"},
		{addr: "evil.example:8200", want: "8200"},
		{addr: "not-an-address", wantErr: true},
	}
	for _, tc := range tests {
		got, err := localHealthPort(tc.addr)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("localHealthPort(%q) expected error", tc.addr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("localHealthPort(%q) error = %v", tc.addr, err)
		}
		if got != tc.want {
			t.Fatalf("localHealthPort(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}