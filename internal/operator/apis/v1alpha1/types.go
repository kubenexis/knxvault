// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Condition types shared by CRDs.
const (
	ConditionReady   = "Ready"
	ConditionIssuing = "Issuing"
)

// AnnotationIngressIssuer triggers Certificate creation from Ingress.
const AnnotationIngressIssuer = "knxvault.kubenexis.dev/issuer"

// AnnotationGatewayIssuer triggers Certificate creation from Gateway TLS.
const AnnotationGatewayIssuer = "knxvault.kubenexis.dev/issuer"

// Issuer kinds / modes for multi-issuer (vault | acme | selfSigned).
const (
	IssuerModeVault      = "Vault"
	IssuerModeACME       = "ACME"
	IssuerModeSelfSigned = "SelfSigned"
)

// IssuerRef references a CA or Issuer for certificate issuance.
type IssuerRef struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// Condition is a standard status condition.
type Condition struct {
	Type               string      `json:"type"`
	Status             string      `json:"status"`
	Reason             string      `json:"reason,omitempty"`
	Message            string      `json:"message,omitempty"`
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
}

// KNXVaultCASpec defines a root or intermediate CA in KNXVault.
type KNXVaultCASpec struct {
	Type       string     `json:"type"`
	CommonName string     `json:"commonName"`
	VaultName  string     `json:"vaultName,omitempty"`
	TTL        string     `json:"ttl,omitempty"`
	KeyBits    int        `json:"keyBits,omitempty"`
	ParentRef  *IssuerRef `json:"parentRef,omitempty"`
}

// KNXVaultCAStatus is observed CA state.
type KNXVaultCAStatus struct {
	Conditions []Condition `json:"conditions,omitempty"`
	CAID       string      `json:"caId,omitempty"`
	Serial     string      `json:"serial,omitempty"`
	NotAfter   string      `json:"notAfter,omitempty"`
	VaultName  string      `json:"vaultName,omitempty"`
}

// KNXVaultCA is the Schema for the knxvaultcas API.
type KNXVaultCA struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              KNXVaultCASpec   `json:"spec,omitempty"`
	Status            KNXVaultCAStatus `json:"status,omitempty"`
}

// KNXVaultCAList contains a list of KNXVaultCA.
type KNXVaultCAList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KNXVaultCA `json:"items"`
}

// VaultIssuerSpec issues from KNXVault PKI (private CA).
type VaultIssuerSpec struct {
	VaultCAName string     `json:"vaultCAName"`
	CARef       *IssuerRef `json:"caRef,omitempty"`
}

// ACMEDNS01Spec configures DNS-01 solvers.
type ACMEDNS01Spec struct {
	// Provider: memory | webhook | cloudflare
	Provider          string        `json:"provider,omitempty"`
	WebhookURL        string        `json:"webhookURL,omitempty"`
	APITokenSecretRef *SecretKeyRef `json:"apiTokenSecretRef,omitempty"`
	ZoneID            string        `json:"zoneID,omitempty"`
}

// SecretKeyRef points at a key in a Secret.
type SecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key,omitempty"`
}

// ACMEIssuerSpec configures ACME (Let's Encrypt / Pebble / other RFC 8555).
type ACMEIssuerSpec struct {
	// Server is the ACME directory URL (default Let's Encrypt production).
	Server string `json:"server,omitempty"`
	Email  string `json:"email,omitempty"`
	// AcceptTOS must be true (W50-07); operator refuses issue when false/absent.
	AcceptTOS bool `json:"acceptTOS,omitempty"`
	// PrivateKeySecretRef stores the ACME account key (optional; generated if missing).
	PrivateKeySecretRef *SecretKeyRef `json:"privateKeySecretRef,omitempty"`
	// SecretNamespace for ClusterIssuer secret refs (defaults to knxvault).
	SecretNamespace string `json:"secretNamespace,omitempty"`
	// Solvers
	HTTP01 bool           `json:"http01,omitempty"`
	DNS01  *ACMEDNS01Spec `json:"dns01,omitempty"`
	// SkipTLSVerify for lab ACME (Pebble); never for public LE.
	SkipTLSVerify bool `json:"skipTLSVerify,omitempty"`
}

// SelfSignedIssuerSpec issues self-signed leaves (no external CA).
type SelfSignedIssuerSpec struct {
	// TTL default certificate lifetime (Go duration), optional.
	TTL string `json:"ttl,omitempty"`
}

// KNXVaultIssuerSpec is multi-issuer: exactly one of vault / acme / selfSigned
// (or legacy vaultCAName for backward compatibility).
type KNXVaultIssuerSpec struct {
	// Legacy single-field vault CA (when Vault/ACME/SelfSigned nil).
	VaultCAName string     `json:"vaultCAName,omitempty"`
	CARef       *IssuerRef `json:"caRef,omitempty"`

	Vault      *VaultIssuerSpec      `json:"vault,omitempty"`
	ACME       *ACMEIssuerSpec       `json:"acme,omitempty"`
	SelfSigned *SelfSignedIssuerSpec `json:"selfSigned,omitempty"`
}

// KNXVaultIssuerStatus is issuer readiness.
type KNXVaultIssuerStatus struct {
	Conditions []Condition `json:"conditions,omitempty"`
	// Mode is Vault | ACME | SelfSigned once resolved.
	Mode string `json:"mode,omitempty"`
}

// KNXVaultIssuer is a namespaced issuer.
type KNXVaultIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              KNXVaultIssuerSpec   `json:"spec,omitempty"`
	Status            KNXVaultIssuerStatus `json:"status,omitempty"`
}

// KNXVaultIssuerList lists issuers.
type KNXVaultIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KNXVaultIssuer `json:"items"`
}

// KNXVaultClusterIssuerSpec is cluster-scoped multi-issuer config.
type KNXVaultClusterIssuerSpec struct {
	VaultCAName string     `json:"vaultCAName,omitempty"`
	CARef       *IssuerRef `json:"caRef,omitempty"`

	Vault      *VaultIssuerSpec      `json:"vault,omitempty"`
	ACME       *ACMEIssuerSpec       `json:"acme,omitempty"`
	SelfSigned *SelfSignedIssuerSpec `json:"selfSigned,omitempty"`
}

// KNXVaultClusterIssuerStatus is cluster issuer readiness.
type KNXVaultClusterIssuerStatus struct {
	Conditions []Condition `json:"conditions,omitempty"`
	Mode       string      `json:"mode,omitempty"`
}

// KNXVaultClusterIssuer is cluster-scoped.
type KNXVaultClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              KNXVaultClusterIssuerSpec   `json:"spec,omitempty"`
	Status            KNXVaultClusterIssuerStatus `json:"status,omitempty"`
}

// KNXVaultClusterIssuerList lists cluster issuers.
type KNXVaultClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KNXVaultClusterIssuer `json:"items"`
}

// PrivateKeySpec configures leaf key generation.
type PrivateKeySpec struct {
	Algorithm string `json:"algorithm,omitempty"`
	Size      int    `json:"size,omitempty"`
}

// Delivery modes for certificate material.
const (
	// DeliverySecret writes kubernetes.io/tls Secret (default; Ingress-compatible).
	DeliverySecret = "Secret"
	// DeliveryNone only updates CR status (no etcd Secret; app fetches via API/CSI).
	DeliveryNone = "None"
)

// KNXVaultCertificateSpec is desired leaf certificate + Secret delivery.
type KNXVaultCertificateSpec struct {
	SecretName           string         `json:"secretName"`
	IssuerRef            IssuerRef      `json:"issuerRef"`
	CommonName           string         `json:"commonName"`
	DNSNames             []string       `json:"dnsNames,omitempty"`
	IPAddresses          []string       `json:"ipAddresses,omitempty"`
	Usages               []string       `json:"usages,omitempty"`
	Duration             string         `json:"duration,omitempty"`
	RenewBefore          string         `json:"renewBefore,omitempty"`
	PrivateKey           PrivateKeySpec `json:"privateKey,omitempty"`
	RevisionHistoryLimit int            `json:"revisionHistoryLimit,omitempty"`
	// Delivery is Secret (default) or None (status-only; no etcd private key).
	Delivery string `json:"delivery,omitempty"`
}

// KNXVaultCertificateStatus is observed certificate state.
type KNXVaultCertificateStatus struct {
	Conditions    []Condition `json:"conditions,omitempty"`
	NotBefore     string      `json:"notBefore,omitempty"`
	NotAfter      string      `json:"notAfter,omitempty"`
	Serial        string      `json:"serial,omitempty"`
	CAID          string      `json:"caId,omitempty"`
	Revision      int         `json:"revision,omitempty"`
	VaultRole     string      `json:"vaultRole,omitempty"`
	NextRenewTime string      `json:"nextRenewTime,omitempty"`
	FailureCount  int         `json:"failureCount,omitempty"`
	LastFailure   string      `json:"lastFailure,omitempty"`
}

// KNXVaultCertificate is a namespaced certificate request to vault + Secret.
type KNXVaultCertificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              KNXVaultCertificateSpec   `json:"spec,omitempty"`
	Status            KNXVaultCertificateStatus `json:"status,omitempty"`
}

// KNXVaultCertificateList lists certificates.
type KNXVaultCertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KNXVaultCertificate `json:"items"`
}

// KNXVaultCertificateRequestSpec signs a provided CSR (operator re-issues via vault when CSR sign is not available).
type KNXVaultCertificateRequestSpec struct {
	Request    string    `json:"request"`
	IssuerRef  IssuerRef `json:"issuerRef"`
	Duration   string    `json:"duration,omitempty"`
	SecretName string    `json:"secretName,omitempty"`
	// CommonName used when falling back to issue (CSR parse optional).
	CommonName string   `json:"commonName,omitempty"`
	DNSNames   []string `json:"dnsNames,omitempty"`
	Usages     []string `json:"usages,omitempty"`
}

// KNXVaultCertificateRequestStatus is CSR / sign result.
type KNXVaultCertificateRequestStatus struct {
	Conditions    []Condition `json:"conditions,omitempty"`
	Certificate   string      `json:"certificate,omitempty"`
	Serial        string      `json:"serial,omitempty"`
	NotAfter      string      `json:"notAfter,omitempty"`
	CACertificate string      `json:"caCertificate,omitempty"`
}

// KNXVaultCertificateRequest is a CSR-style request.
type KNXVaultCertificateRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              KNXVaultCertificateRequestSpec   `json:"spec,omitempty"`
	Status            KNXVaultCertificateRequestStatus `json:"status,omitempty"`
}

// KNXVaultCertificateRequestList lists CSR requests.
type KNXVaultCertificateRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KNXVaultCertificateRequest `json:"items"`
}

// Ensure types implement runtime.Object.
var (
	_ runtime.Object = &KNXVaultCA{}
	_ runtime.Object = &KNXVaultCAList{}
	_ runtime.Object = &KNXVaultIssuer{}
	_ runtime.Object = &KNXVaultIssuerList{}
	_ runtime.Object = &KNXVaultClusterIssuer{}
	_ runtime.Object = &KNXVaultClusterIssuerList{}
	_ runtime.Object = &KNXVaultCertificate{}
	_ runtime.Object = &KNXVaultCertificateList{}
	_ runtime.Object = &KNXVaultCertificateRequest{}
	_ runtime.Object = &KNXVaultCertificateRequestList{}
)
