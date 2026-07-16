// Package secretutil builds kubernetes.io/tls Secrets for the operator.
package secretutil

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TLSSecret builds a kubernetes.io/tls Secret body.
func TLSSecret(namespace, name, certPEM, keyPEM, caPEM string, labels map[string]string) *corev1.Secret {
	if labels == nil {
		labels = map[string]string{}
	}
	labels["app.kubernetes.io/managed-by"] = "knxvault-operator"
	data := map[string][]byte{
		corev1.TLSCertKey:       []byte(certPEM),
		corev1.TLSPrivateKeyKey: []byte(keyPEM),
	}
	if caPEM != "" {
		data["ca.crt"] = []byte(caPEM)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Type: corev1.SecretTypeTLS,
		Data: data,
	}
}

// CertOnlySecret stores a signed cert without private key (CSR flow).
func CertOnlySecret(namespace, name, certPEM, caPEM string) *corev1.Secret {
	data := map[string][]byte{
		"tls.crt": []byte(certPEM),
	}
	if caPEM != "" {
		data["ca.crt"] = []byte(caPEM)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "knxvault-operator",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
}
