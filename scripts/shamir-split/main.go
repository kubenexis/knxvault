// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Offline Shamir split helper for lab / ops ceremonies.
// Usage: go run ./scripts/shamir-split -key <base64-secret> -n 3 -t 2
// Prints base64 shares, one per line (suitable for /sys/unseal {"share":"..."}).
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/kubenexis/knxvault/internal/crypto/shamir"
)

func main() {
	keyB64 := flag.String("key", "", "base64-encoded secret (same encoding as KNXVAULT_UNSEAL_KEY)")
	n := flag.Int("n", 3, "number of shares")
	t := flag.Int("t", 2, "threshold")
	flag.Parse()
	if *keyB64 == "" {
		fmt.Fprintln(os.Stderr, "usage: shamir-split -key <base64> [-n 3] [-t 2]")
		os.Exit(2)
	}
	secret, err := base64.StdEncoding.DecodeString(*keyB64)
	if err != nil || len(secret) == 0 {
		fmt.Fprintf(os.Stderr, "invalid base64 key: %v\n", err)
		os.Exit(1)
	}
	parts, err := shamir.Split(secret, *n, *t)
	if err != nil {
		fmt.Fprintf(os.Stderr, "split: %v\n", err)
		os.Exit(1)
	}
	for _, p := range parts {
		fmt.Println(base64.StdEncoding.EncodeToString(p))
	}
}
