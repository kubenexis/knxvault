// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
)

func TestResolveVaultRole(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)

	ca := &v1alpha1.KNXVaultCA{
		ObjectMeta: metav1.ObjectMeta{Name: "root", Namespace: "knxvault"},
		Spec:       v1alpha1.KNXVaultCASpec{VaultName: "platform-root"},
		Status:     v1alpha1.KNXVaultCAStatus{VaultName: "platform-root"},
	}
	iss := &v1alpha1.KNXVaultIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "app-iss", Namespace: "default"},
		Spec:       v1alpha1.KNXVaultIssuerSpec{VaultCAName: "platform-root"},
	}
	ci := &v1alpha1.KNXVaultClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-iss"},
		Spec:       v1alpha1.KNXVaultClusterIssuerSpec{VaultCAName: "platform-root"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ca, iss, ci).Build()

	role, err := ResolveVaultRole(context.Background(), c, "default", v1alpha1.IssuerRef{
		Kind: "KNXVaultIssuer", Name: "app-iss",
	})
	if err != nil || role != "platform-root" {
		t.Fatalf("issuer: %v %q", err, role)
	}
	role, err = ResolveVaultRole(context.Background(), c, "default", v1alpha1.IssuerRef{
		Kind: "KNXVaultClusterIssuer", Name: "cluster-iss",
	})
	if err != nil || role != "platform-root" {
		t.Fatalf("clusterissuer: %v %q", err, role)
	}
	role, err = ResolveVaultRole(context.Background(), c, "default", v1alpha1.IssuerRef{
		Kind: "KNXVaultCA", Name: "root", Namespace: "knxvault",
	})
	if err != nil || role != "platform-root" {
		t.Fatalf("ca: %v %q", err, role)
	}
}
