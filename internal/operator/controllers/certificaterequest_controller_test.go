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

func TestCertificateRequestReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	ci := &v1alpha1.KNXVaultClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "platform"},
		Spec:       v1alpha1.KNXVaultClusterIssuerSpec{VaultCAName: "root"},
	}
	cr := &v1alpha1.KNXVaultCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "req", Namespace: "default"},
		Spec: v1alpha1.KNXVaultCertificateRequestSpec{
			CommonName: "device.example.com",
			SecretName: "device-cert",
			IssuerRef:  v1alpha1.IssuerRef{Kind: "KNXVaultClusterIssuer", Name: "platform"},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(cr, ci).WithObjects(ci, cr).Build()
	r := &CertificateRequestReconciler{Client: c, Scheme: scheme, Vault: vaultiface.NewFake()}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "req"}})
	if err != nil {
		t.Fatal(err)
	}
	var out v1alpha1.KNXVaultCertificateRequest
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "req"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.Status.Serial == "" {
		t.Fatalf("%+v", out.Status)
	}
}
