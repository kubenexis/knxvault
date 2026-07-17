// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

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
	self := &v1alpha1.KNXVaultClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "self"},
		Spec:       v1alpha1.KNXVaultClusterIssuerSpec{SelfSigned: &v1alpha1.SelfSignedIssuerSpec{}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(iss, ci, self).WithObjects(iss, ci, self).Build()
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
	_, err = (&ClusterIssuerReconciler{Client: c, Vault: v}).Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "self"}})
	if err != nil {
		t.Fatal(err)
	}
	var out v1alpha1.KNXVaultClusterIssuer
	if err := c.Get(context.Background(), types.NamespacedName{Name: "self"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.Status.Mode != v1alpha1.IssuerModeSelfSigned {
		t.Fatalf("mode=%s", out.Status.Mode)
	}
}

func TestIssuerACMEDisabledByDefault(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	iss := &v1alpha1.KNXVaultIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "le", Namespace: "ns"},
		Spec: v1alpha1.KNXVaultIssuerSpec{
			ACME: &v1alpha1.ACMEIssuerSpec{Server: "https://acme.example/dir", HTTP01: true},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(iss).WithObjects(iss).Build()
	// ACMEEnabled false (zero value) must reject ACME issuers.
	_, err := (&IssuerReconciler{Client: c, Vault: vaultiface.NewFake(), ACMEEnabled: false}).Reconcile(
		context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "le"}})
	if err != nil {
		t.Fatal(err)
	}
	var out v1alpha1.KNXVaultIssuer
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: "le"}, &out); err != nil {
		t.Fatal(err)
	}
	ready := false
	for _, cond := range out.Status.Conditions {
		if cond.Type == v1alpha1.ConditionReady && cond.Status == "False" {
			ready = true
			if cond.Message == "" {
				t.Fatal("expected Ready=False message about ACME disabled")
			}
		}
	}
	if !ready {
		t.Fatalf("expected Ready=False for disabled ACME, conditions=%+v", out.Status.Conditions)
	}
}
