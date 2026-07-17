// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestLoginWithClientCert(t *testing.T) {
	store := auth.NewTokenStore(time.Hour)
	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name: "web-client", Effect: domainauth.EffectAllow,
		Resources: []string{"*"}, Actions: []string{"*"},
	})
	svc := auth.NewService(store, rbac, "")
	svc.SetRoleResolver(staticRole{"web-client": []string{"web-client"}})

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "web-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"web-client.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	token, rec, err := svc.LoginWithClientCert(context.Background(), []*x509.Certificate{cert}, auth.CertLoginOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || rec == nil {
		t.Fatal("empty token")
	}
	if _, _, err := svc.LoginWithClientCert(context.Background(), nil, auth.CertLoginOptions{}); err == nil {
		t.Fatal("expected missing cert error")
	}
}

type staticRole map[string][]string

func (s staticRole) PoliciesForRole(_ context.Context, role string) []string {
	return s[role]
}
