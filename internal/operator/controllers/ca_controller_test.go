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

func TestCAReconcilerRoot(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	ca := &v1alpha1.KNXVaultCA{
		ObjectMeta: metav1.ObjectMeta{Name: "root", Namespace: "knxvault"},
		Spec:       v1alpha1.KNXVaultCASpec{Type: "root", CommonName: "Root CA", VaultName: "platform-root"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(ca).WithObjects(ca).Build()
	r := &CAReconciler{Client: c, Vault: vaultiface.NewFake()}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "knxvault", Name: "root"}})
	if err != nil {
		t.Fatal(err)
	}
	var out v1alpha1.KNXVaultCA
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "knxvault", Name: "root"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.Status.CAID == "" || out.Status.VaultName != "platform-root" {
		t.Fatalf("status = %+v", out.Status)
	}
}
