// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package handlers

import "testing"

func TestValidExposureLeaseID(t *testing.T) {
	if !validExposureLeaseID("ns-a.lease1") {
		t.Fatal("expected valid")
	}
	if validExposureLeaseID("ab") {
		t.Fatal("too short")
	}
	if validExposureLeaseID("bad;drop") {
		t.Fatal("invalid chars")
	}
}

func TestExposurePathAllowed(t *testing.T) {
	if exposurePathAllowed("app/db", nil) {
		t.Fatal("empty prefixes deny")
	}
	if !exposurePathAllowed("app/db", []string{"app/"}) {
		t.Fatal("prefix match")
	}
	if exposurePathAllowed("../etc", []string{"app/"}) {
		t.Fatal("traversal")
	}
	if exposurePathAllowed("other/x", []string{"app/"}) {
		t.Fatal("wrong prefix")
	}
}
