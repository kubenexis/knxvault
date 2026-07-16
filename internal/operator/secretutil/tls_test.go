package secretutil

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestTLSSecret(t *testing.T) {
	t.Parallel()
	s := TLSSecret("ns", "app-tls", "CERT", "KEY", "CA", "ser1", "2026-10-01T00:00:00Z", "ca-1", 2, nil)
	if s.Annotations[AnnSerial] != "ser1" || s.Annotations[AnnCAID] != "ca-1" {
		t.Fatalf("anns=%v", s.Annotations)
	}
	if s.Type != corev1.SecretTypeTLS {
		t.Fatalf("type = %s", s.Type)
	}
	if string(s.Data[corev1.TLSCertKey]) != "CERT" {
		t.Fatal("cert")
	}
	if string(s.Data[corev1.TLSPrivateKeyKey]) != "KEY" {
		t.Fatal("key")
	}
	if string(s.Data["ca.crt"]) != "CA" {
		t.Fatal("ca")
	}
	if s.Labels["app.kubernetes.io/managed-by"] != "knxvault-operator" {
		t.Fatal("label")
	}
}

func TestCertOnlySecret(t *testing.T) {
	t.Parallel()
	s := CertOnlySecret("ns", "csr-out", "CERT", "CA")
	if string(s.Data["tls.crt"]) != "CERT" {
		t.Fatal("cert")
	}
	if _, ok := s.Data[corev1.TLSPrivateKeyKey]; ok {
		t.Fatal("should not have private key")
	}
}
