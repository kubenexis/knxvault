// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"time"

	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	gossh "golang.org/x/crypto/ssh"
)

// CertOptions configures an OpenSSH user certificate.
type CertOptions struct {
	KeyID           string
	Principals      []string
	ValidAfter      time.Time
	ValidBefore     time.Time
	Extensions      map[string]string
	CriticalOptions map[string]string
}

func parseCAPrivateKey(pemBytes []byte) (gossh.Signer, error) {
	signer, err := gossh.ParsePrivateKey(pemBytes)
	if err == nil {
		return signer, nil
	}
	raw, err := gossh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca private key: %w", err)
	}
	return gossh.NewSignerFromKey(raw)
}

func generateUserKeyPEM(keyType string) (gossh.Signer, []byte, error) {
	switch keyType {
	case "", domainsecrets.SSHKeyTypeED25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return marshalSignerFromKey(priv)
	case domainsecrets.SSHKeyTypeRSA:
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, err
		}
		return marshalSignerFromKey(key)
	default:
		return nil, nil, fmt.Errorf("unsupported key type %q", keyType)
	}
}

func marshalSignerFromKey(key any) (gossh.Signer, []byte, error) {
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		return nil, nil, err
	}
	block, err := gossh.MarshalPrivateKey(key, "")
	if err != nil {
		return nil, nil, err
	}
	return signer, pem.EncodeToMemory(block), nil
}

func signUserCertificate(caSigner, userSigner gossh.Signer, opts CertOptions) ([]byte, error) {
	validAfter, err := certEpochSeconds(opts.ValidAfter)
	if err != nil {
		return nil, err
	}
	validBefore, err := certEpochSeconds(opts.ValidBefore)
	if err != nil {
		return nil, err
	}

	pub := userSigner.PublicKey()
	cert := &gossh.Certificate{
		Key:             pub,
		Serial:          randomSerial(),
		CertType:        gossh.UserCert,
		KeyId:           opts.KeyID,
		ValidPrincipals: append([]string(nil), opts.Principals...),
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
		Permissions: gossh.Permissions{
			Extensions:      copyStringMap(opts.Extensions),
			CriticalOptions: copyStringMap(opts.CriticalOptions),
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, fmt.Errorf("sign ssh certificate: %w", err)
	}
	return gossh.MarshalAuthorizedKey(cert), nil
}

func parseUserSigner(pemBytes []byte) (gossh.Signer, error) {
	signer, err := gossh.ParsePrivateKey(pemBytes)
	if err == nil {
		return signer, nil
	}
	raw, err := gossh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse user private key: %w", err)
	}
	return gossh.NewSignerFromKey(raw)
}

// certEpochSeconds maps a time to OpenSSH certificate epoch seconds (uint64).
func certEpochSeconds(t time.Time) (uint64, error) {
	sec := t.Unix()
	if sec < 0 {
		return 0, fmt.Errorf("certificate time %s is before unix epoch", t.UTC().Format(time.RFC3339))
	}
	return uint64(sec), nil
}

func randomSerial() uint64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		sum := sha256.Sum256([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
		return binary.BigEndian.Uint64(sum[:8])
	}
	var out uint64
	for _, b := range buf {
		out = out<<8 | uint64(b)
	}
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
