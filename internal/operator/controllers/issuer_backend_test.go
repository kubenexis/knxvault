package controllers

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kubenexis/knxvault/internal/acme"
	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
	"github.com/kubenexis/knxvault/internal/operator/vaultiface"
)

func TestIssueFromResolvedSelfSigned(t *testing.T) {
	res, err := IssueFromResolved(context.Background(), nil, nil, "ns",
		v1alpha1.ResolvedIssuer{Mode: v1alpha1.IssuerModeSelfSigned, SelfSigned: &v1alpha1.SelfSignedIssuerSpec{TTL: "24h"}},
		"app.local", []string{"app.local"}, nil, "24h", 2048, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.CertPEM == "" || res.Serial == "" {
		t.Fatalf("%+v", res)
	}
}

func TestIssueFromResolvedVault(t *testing.T) {
	v := vaultiface.NewFake()
	_, _ = v.CreateRoot(context.Background(), "root", "Root", "8760h", 2048)
	res, err := IssueFromResolved(context.Background(), nil, v, "ns",
		v1alpha1.ResolvedIssuer{Mode: v1alpha1.IssuerModeVault, VaultCA: "root"},
		"app.local", []string{"app.local"}, nil, "24h", 2048, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.CertPEM == "" {
		t.Fatal("empty cert")
	}
}

func TestResolveIssuerFromRefSelfSigned(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	ci := &v1alpha1.KNXVaultClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "ss"},
		Spec:       v1alpha1.KNXVaultClusterIssuerSpec{SelfSigned: &v1alpha1.SelfSignedIssuerSpec{}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ci).Build()
	r, err := ResolveIssuerFromRef(context.Background(), c, "default", v1alpha1.IssuerRef{Kind: "KNXVaultClusterIssuer", Name: "ss"})
	if err != nil || r.Mode != v1alpha1.IssuerModeSelfSigned {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestLoadStoreACMEAccountKey(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := context.Background()
	ref := &v1alpha1.SecretKeyRef{Name: "acme-account", Key: "tls.key"}

	key, err := acme.GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := storeACMEAccountKey(ctx, c, "knxvault", ref, key); err != nil {
		t.Fatalf("store: %v", err)
	}
	loaded, err := loadACMEAccountKey(ctx, c, "knxvault", ref)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded == nil {
		t.Fatal("nil key")
	}
	// Update path
	key2, _ := acme.GenerateAccountKey()
	if err := storeACMEAccountKey(ctx, c, "knxvault", ref, key2); err != nil {
		t.Fatalf("store update: %v", err)
	}
	var sec corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Namespace: "knxvault", Name: "acme-account"}, &sec); err != nil {
		t.Fatal(err)
	}
	if len(sec.Data["tls.key"]) == 0 {
		t.Fatal("empty secret data")
	}
}
