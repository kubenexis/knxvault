// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/vaultiface"
)

func TestCertificateReconcilerIssue(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)

	iss := &v1alpha1.KNXVaultClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "platform"},
		Spec:       v1alpha1.KNXVaultClusterIssuerSpec{VaultCAName: "platform-root"},
	}
	cert := &v1alpha1.KNXVaultCertificate{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec: v1alpha1.KNXVaultCertificateSpec{
			SecretName:  "app-tls",
			CommonName:  "app.example.com",
			DNSNames:    []string{"app.example.com"},
			Duration:    "720h",
			RenewBefore: "24h",
			IssuerRef:   v1alpha1.IssuerRef{Kind: "KNXVaultClusterIssuer", Name: "platform"},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(cert, iss).WithObjects(iss, cert).Build()
	r := &CertificateReconciler{Client: c, Scheme: scheme, Vault: vaultiface.NewFake()}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "app"}})
	if err != nil {
		t.Fatal(err)
	}
	var out v1alpha1.KNXVaultCertificate
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "app"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.Status.Serial == "" || out.Status.Revision != 1 {
		t.Fatalf("status=%+v", out.Status)
	}
}
