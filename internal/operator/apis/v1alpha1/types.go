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

// KNXVaultIssuerSpec references a vault CA for namespaced issuance.
type KNXVaultIssuerSpec struct {
	VaultCAName string     `json:"vaultCAName"`
	CARef       *IssuerRef `json:"caRef,omitempty"`
}

// KNXVaultIssuerStatus is issuer readiness.
type KNXVaultIssuerStatus struct {
	Conditions []Condition `json:"conditions,omitempty"`
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

// KNXVaultClusterIssuerSpec is cluster-scoped issuer config.
type KNXVaultClusterIssuerSpec struct {
	VaultCAName string     `json:"vaultCAName"`
	CARef       *IssuerRef `json:"caRef,omitempty"`
}

// KNXVaultClusterIssuerStatus is cluster issuer readiness.
type KNXVaultClusterIssuerStatus struct {
	Conditions []Condition `json:"conditions,omitempty"`
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
}

// KNXVaultCertificateStatus is observed certificate state.
type KNXVaultCertificateStatus struct {
	Conditions []Condition `json:"conditions,omitempty"`
	NotBefore  string      `json:"notBefore,omitempty"`
	NotAfter   string      `json:"notAfter,omitempty"`
	Serial     string      `json:"serial,omitempty"`
	CAID       string      `json:"caId,omitempty"`
	Revision   int         `json:"revision,omitempty"`
	VaultRole  string      `json:"vaultRole,omitempty"`
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
