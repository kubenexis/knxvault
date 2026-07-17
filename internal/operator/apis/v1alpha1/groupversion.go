// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package v1alpha1 defines KNXVault operator CRD API types.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	Group   = "knxvault.kubenexis.dev"
	Version = "v1alpha1"
)

// SchemeGroupVersion is group version used to register these objects.
var SchemeGroupVersion = schema.GroupVersion{Group: Group, Version: Version}

// SchemeBuilder registers types with a scheme.
var (
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&KNXVaultCA{}, &KNXVaultCAList{},
		&KNXVaultIssuer{}, &KNXVaultIssuerList{},
		&KNXVaultClusterIssuer{}, &KNXVaultClusterIssuerList{},
		&KNXVaultCertificate{}, &KNXVaultCertificateList{},
		&KNXVaultCertificateRequest{}, &KNXVaultCertificateRequestList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// Resource returns a GroupResource for the given resource name.
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}
