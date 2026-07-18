// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/vaultiface"
)

func TestSecretOwnedByCertificateOwnerRefOnly(t *testing.T) {
	cert := &v1alpha1.KNXVaultCertificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: "default",
			UID:       types.UID("cert-uid-1"),
		},
	}
	// Label spoof without OwnerRef must not count as owned (W86-03).
	spoofed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-tls",
			Namespace: "default",
			Labels: map[string]string{
				"knxvault.kubenexis.dev/certificate": "app",
			},
		},
	}
	if secretOwnedByCertificate(spoofed, cert) {
		t.Fatal("label-only Secret must not be considered owned")
	}

	owned := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-tls",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "knxvault.kubenexis.dev/v1alpha1",
				Kind:       "KNXVaultCertificate",
				Name:       cert.Name,
				UID:        cert.UID,
				Controller: ptr.To(true),
			}},
		},
	}
	if !secretOwnedByCertificate(owned, cert) {
		t.Fatal("OwnerRef controller should count as owned")
	}
}

func TestApplyTLSSecretRefusesLabelOnlySpoof(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)

	cert := &v1alpha1.KNXVaultCertificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: "default",
			UID:       types.UID("cert-uid-2"),
		},
		Spec: v1alpha1.KNXVaultCertificateSpec{
			SecretName: "app-tls",
			CommonName: "app.example",
		},
	}
	// Pre-existing Secret with spoof label but no OwnerRef (e.g. attacker-created).
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-tls",
			Namespace: "default",
			Labels: map[string]string{
				"knxvault.kubenexis.dev/certificate": "app",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte("old-cert"),
			corev1.TLSPrivateKeyKey: []byte("old-key"),
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cert, existing).Build()
	r := &CertificateReconciler{Client: c, Scheme: scheme, Vault: vaultiface.NewFake()}
	err := r.applyTLSSecret(context.Background(), cert, &vaultiface.CertResult{
		CertPEM: "new-cert", PrivateKeyPEM: "new-key", Serial: "1", ExpiresAt: "2099-01-01T00:00:00Z",
	}, "ca1", 1)
	if err == nil {
		t.Fatal("expected refuse overwrite for label-only spoofed Secret")
	}
	var out corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "app-tls"}, &out); err != nil {
		t.Fatal(err)
	}
	if string(out.Data[corev1.TLSCertKey]) != "old-cert" {
		t.Fatalf("secret was overwritten: %q", out.Data[corev1.TLSCertKey])
	}
}
