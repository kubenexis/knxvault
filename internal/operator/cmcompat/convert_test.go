package cmcompat_test

import (
	"testing"

	v1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/cmcompat"
)

func TestConvertCertificate(t *testing.T) {
	spec, err := cmcompat.ConvertCertificate(cmcompat.CMCertificate{
		SecretName: "tls",
		DNSNames:   []string{"a.example.com"},
		IssuerRef:  cmcompat.CMIssuerRef{Name: "letsencrypt", Kind: "ClusterIssuer", Group: "cert-manager.io"},
		Duration:   "2160h",
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec.CommonName != "a.example.com" || spec.IssuerRef.Kind != "KNXVaultClusterIssuer" {
		t.Fatalf("%+v", spec)
	}
}

func TestConvertIssuerTypes(t *testing.T) {
	v, err := cmcompat.ConvertIssuer(cmcompat.CMIssuer{Type: "vault", VaultCAName: "web"})
	if err != nil || v.Vault == nil || v.Vault.VaultCAName != "web" {
		t.Fatalf("%+v %v", v, err)
	}
	a, err := cmcompat.ConvertIssuer(cmcompat.CMIssuer{Type: "acme", ACMEServer: "https://acme", HTTP01: true})
	if err != nil || a.ACME == nil || !a.ACME.HTTP01 {
		t.Fatalf("%+v %v", a, err)
	}
	s, err := cmcompat.ConvertIssuer(cmcompat.CMIssuer{SelfSigned: true})
	if err != nil || s.SelfSigned == nil {
		t.Fatalf("%+v %v", s, err)
	}
	c, err := cmcompat.ConvertClusterIssuer(cmcompat.CMIssuer{Type: "selfsigned"})
	if err != nil || c.SelfSigned == nil {
		t.Fatalf("%+v %v", c, err)
	}
	if c.SelfSigned == nil {
		t.Fatal("expected selfsigned")
	}
	_ = v1.IssuerModeSelfSigned
}

func TestConvertCertificateErrors(t *testing.T) {
	if _, err := cmcompat.ConvertCertificate(cmcompat.CMCertificate{}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := cmcompat.ConvertIssuer(cmcompat.CMIssuer{Type: "vault"}); err == nil {
		t.Fatal("expected vaultCAName")
	}
}
