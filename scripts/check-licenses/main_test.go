// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectLicense(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{"apache", "Licensed under the Apache License, Version 2.0", "Apache-2.0"},
		{"mit", "MIT License\nPermission is hereby granted, free of charge", "MIT"},
		{"spdx-bsd3", "SPDX-License-Identifier: BSD-3-Clause", "BSD-3-Clause"},
		{"unknown", "Proprietary All Rights Reserved", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detectLicense(tc.text); got != tc.want {
				t.Fatalf("detectLicense = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoadAllowList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow")
	content := "# comment\n\nApache-2.0\nMIT\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	allowed, err := loadAllowList(path)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed["Apache-2.0"] || !allowed["MIT"] {
		t.Fatalf("allow-list = %#v", allowed)
	}
	if allowed["GPL-3.0"] {
		t.Fatal("unexpected GPL")
	}
}

func TestLoadAllowListEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow")
	if err := os.WriteFile(path, []byte("# only comments\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAllowList(path); err == nil {
		t.Fatal("expected empty allow-list error")
	}
}

func TestModuleLicenseOverrides(t *testing.T) {
	// Override path must stay wired for modules without standard LICENSE files.
	if moduleLicenseOverrides["github.com/pkg/errors"] != "BSD-2-Clause" {
		t.Fatal("pkg/errors override missing")
	}
}
