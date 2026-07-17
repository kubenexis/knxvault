// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewLoggerLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", ""} {
		log, err := newLogger(level)
		if err != nil {
			t.Fatalf("level %q: %v", level, err)
		}
		_ = log.Sync()
	}
}

func TestRootHelp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--help"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "serve") {
		t.Fatalf("help missing serve: %s", out)
	}
}

func TestRootVersion(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) == "" {
		t.Fatal("empty version output")
	}
}
