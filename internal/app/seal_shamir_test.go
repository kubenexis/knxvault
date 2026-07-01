package app_test

import (
	"encoding/base64"
	"testing"

	"github.com/kubenexis/knxvault/internal/app"
	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/crypto/shamir"
)

func TestSealStateShamirUnseal(t *testing.T) {
	secret := []byte("unseal-key-material-32-bytes!!")
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	seal := app.NewSealStateFromConfig(config.SealConfig{
		Scheme:    config.UnsealSchemeShamir,
		Threshold: 3,
		Shares:    5,
	}, nil, nil)
	if !seal.Sealed() {
		t.Fatal("expected sealed initially")
	}
	for i, share := range shares[:2] {
		ok, progress, threshold := seal.SubmitShare(i+1, share)
		if ok || progress != i+1 || threshold != 3 {
			t.Fatalf("share %d: ok=%v progress=%d threshold=%d", i+1, ok, progress, threshold)
		}
	}
	ok, progress, threshold := seal.SubmitShare(3, shares[2])
	if !ok || progress != 3 || threshold != 3 {
		t.Fatalf("final share: ok=%v progress=%d threshold=%d", ok, progress, threshold)
	}
	if seal.Sealed() {
		t.Fatal("expected unsealed")
	}
	_ = base64.StdEncoding
}
