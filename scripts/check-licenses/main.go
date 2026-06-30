// Command check-licenses enforces the permissive SPDX allow-list (docs/licensing.md).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type module struct {
	Path    string
	Version string
}

type packageInfo struct {
	Module *module `json:"Module"`
}

var licensePatterns = []struct {
	spdx    string
	matches []*regexp.Regexp
}{
	{spdx: "Apache-2.0", matches: []*regexp.Regexp{
		regexp.MustCompile(`(?i)Apache License, Version 2\.0`),
		regexp.MustCompile(`(?is)Apache License\s+Version 2\.0`),
		regexp.MustCompile(`(?i)Licensed under the Apache License, Version 2\.0`),
		regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*Apache-2\.0`),
	}},
	{spdx: "MIT", matches: []*regexp.Regexp{
		regexp.MustCompile(`(?i)MIT License`),
		regexp.MustCompile(`(?i)Permission is hereby granted, free of charge`),
		regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*MIT`),
	}},
	{spdx: "BSD-2-Clause", matches: []*regexp.Regexp{
		regexp.MustCompile(`(?i)BSD 2-Clause`),
		regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*BSD-2-Clause`),
		regexp.MustCompile(`(?is)Redistribution and use in source and binary forms.+THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"`),
	}},
	{spdx: "BSD-3-Clause", matches: []*regexp.Regexp{
		regexp.MustCompile(`(?i)BSD 3-Clause`),
		regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*BSD-3-Clause`),
		regexp.MustCompile(`(?is)Redistribution and use in source and binary forms.+Neither the name`),
	}},
	{spdx: "ISC", matches: []*regexp.Regexp{
		regexp.MustCompile(`(?i)ISC License`),
		regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*ISC`),
	}},
	{spdx: "Unicode-3.0", matches: []*regexp.Regexp{
		regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*Unicode-3\.0`),
	}},
	{spdx: "0BSD", matches: []*regexp.Regexp{
		regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*0BSD`),
	}},
	{spdx: "CC0-1.0", matches: []*regexp.Regexp{
		regexp.MustCompile(`(?i)CC0 1\.0`),
		regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*CC0-1\.0`),
	}},
	{spdx: "MPL-2.0", matches: []*regexp.Regexp{
		regexp.MustCompile(`(?i)Mozilla Public License,?\s+version 2\.0`),
		regexp.MustCompile(`(?i)Mozilla Public License Version 2\.0`),
		regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*MPL-2\.0`),
	}},
	{spdx: "LGPL-3.0", matches: []*regexp.Regexp{
		regexp.MustCompile(`(?i)GNU Lesser General Public License`),
		regexp.MustCompile(`(?i)SPDX-License-Identifier:\s*LGPL-3\.0`),
	}},
}

// moduleLicenseOverrides maps modules without standard LICENSE files to SPDX IDs.
var moduleLicenseOverrides = map[string]string{
	"github.com/pkg/errors":            "BSD-2-Clause",
	"github.com/cockroachdb/sentry-go": "BSD-3-Clause",
	"github.com/magiconair/properties": "BSD-2-Clause",
}

func main() {
	root, err := repoRoot()
	if err != nil {
		fail(err)
	}

	allowed, err := loadAllowList(filepath.Join(root, "config", "licenses.allow"))
	if err != nil {
		fail(err)
	}

	modules, err := listModules(root)
	if err != nil {
		fail(err)
	}

	var violations []string
	for _, mod := range modules {
		if mod.Path == "" || !strings.Contains(mod.Path, ".") {
			continue
		}

		license, err := moduleLicense(root, mod)
		if err != nil {
			violations = append(violations, fmt.Sprintf("%s@%s: %v", mod.Path, mod.Version, err))
			continue
		}
		if !allowed[license] {
			violations = append(violations, fmt.Sprintf("%s@%s: license %q not allowed", mod.Path, mod.Version, license))
		}
	}

	if len(violations) > 0 {
		fmt.Fprintln(os.Stderr, "license check failed:")
		for _, v := range violations {
			fmt.Fprintln(os.Stderr, "  -", v)
		}
		os.Exit(1)
	}

	fmt.Println("==> License check passed")
}

func repoRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w", err)
	}
	modPath := strings.TrimSpace(string(out))
	if modPath == "" {
		return "", fmt.Errorf("not inside a Go module")
	}
	return filepath.Dir(modPath), nil
}

func loadAllowList(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open allow-list: %w", err)
	}
	defer func() { _ = f.Close() }()

	allowed := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allowed[line] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("allow-list is empty")
	}
	return allowed, nil
}

func listModules(root string) ([]module, error) {
	cmd := exec.Command("go", "list", "-deps", "-json", "./...")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -deps -json ./...: %w", err)
	}

	seen := make(map[string]module)
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var pkg packageInfo
		if err := dec.Decode(&pkg); err != nil {
			return nil, fmt.Errorf("decode package: %w", err)
		}
		if pkg.Module == nil || pkg.Module.Path == "" {
			continue
		}
		seen[pkg.Module.Path] = *pkg.Module
	}

	modules := make([]module, 0, len(seen))
	for _, mod := range seen {
		modules = append(modules, mod)
	}
	return modules, nil
}

func moduleLicense(root string, mod module) (string, error) {
	if spdx, ok := moduleLicenseOverrides[mod.Path]; ok {
		return spdx, nil
	}

	version := mod.Version
	if version == "" {
		version = "latest"
	}

	cmd := exec.Command("go", "mod", "download", "-json", mod.Path+"@"+version)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("download module: %w", err)
	}

	var info struct {
		Dir string `json:"Dir"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return "", fmt.Errorf("decode download info: %w", err)
	}
	if info.Dir == "" {
		return "", fmt.Errorf("empty module dir")
	}

	entries, err := os.ReadDir(info.Dir)
	if err != nil {
		return "", fmt.Errorf("read module dir: %w", err)
	}

	candidates := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToUpper(entry.Name())
		if strings.HasPrefix(name, "LICENSE") || name == "COPYING" {
			candidates = append(candidates, entry.Name())
		}
	}

	for _, file := range candidates {
		content, err := os.ReadFile(filepath.Join(info.Dir, file))
		if err != nil {
			return "", err
		}
		if spdx := detectLicense(string(content)); spdx != "" {
			return spdx, nil
		}
	}

	return "", fmt.Errorf("no recognized license file in %s", info.Dir)
}

func detectLicense(content string) string {
	for _, pattern := range licensePatterns {
		for _, re := range pattern.matches {
			if re.MatchString(content) {
				return pattern.spdx
			}
		}
	}
	return ""
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
