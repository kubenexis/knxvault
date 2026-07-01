package shamir_test

import (
	"crypto/rand"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto/shamir"
)

func TestSplitCombineRoundTrip(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	got, err := shamir.Combine([][]byte{shares[0], shares[2], shares[4]})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secret) {
		t.Fatal("reconstructed secret mismatch")
	}
}

func TestCombineInsufficientShares(t *testing.T) {
	secret := []byte("unseal-key-material-32-bytes!!")
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	got, err := shamir.Combine(shares[:2])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == string(secret) {
		t.Fatal("two shares must not reconstruct the secret when threshold is 3")
	}
}

func TestVerifySplitRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	if err := shamir.VerifySplitRoundTrip(secret, 5, 3); err != nil {
		t.Fatal(err)
	}
}
