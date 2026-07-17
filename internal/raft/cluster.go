// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseInitialMembers parses KNXVAULT_RAFT_INITIAL_MEMBERS.
// Format: "1=host1:63001,2=host2:63001,3=host3:63001"
func ParseInitialMembers(raw string) (map[uint64]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	out := make(map[uint64]string)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid raft member %q", part)
		}
		id, err := strconv.ParseUint(strings.TrimSpace(kv[0]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid raft node id %q: %w", kv[0], err)
		}
		addr := strings.TrimSpace(kv[1])
		if addr == "" {
			return nil, fmt.Errorf("raft member %d address is required", id)
		}
		out[id] = addr
	}
	return out, nil
}
