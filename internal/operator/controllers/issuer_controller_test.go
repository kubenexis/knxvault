package controllers

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/vaultiface"
)

func TestIssuerAndClusterIssuer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	iss := &v1alpha1.KNXVaultIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "i", Namespace: "ns"},
		Spec:       v1alpha1.KNXVaultIssuerSpec{VaultCAName: "root"},
	}
	ci := &v1alpha1.KNXVaultClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "c"},
		Spec:       v1alpha1.KNXVaultClusterIssuerSpec{VaultCAName: "root"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(iss, ci).WithObjects(iss, ci).Build()
	v := vaultiface.NewFake()
	_, _ = v.CreateRoot(context.Background(), "root", "Root", "8760h", 2048)
	_, err := (&IssuerReconciler{Client: c, Vault: v}).Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "i"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&ClusterIssuerReconciler{Client: c, Vault: v}).Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "c"}})
	if err != nil {
		t.Fatal(err)
	}
}
