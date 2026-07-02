package dto

// CreateRootCARequest is POST /pki/root.
type CreateRootCARequest struct {
	Name       string `json:"name" binding:"required"`
	CommonName string `json:"common_name" binding:"required"`
	TTL        string `json:"ttl" binding:"required"`
	KeyType    string `json:"key_type"`
	KeyBits    int    `json:"key_bits"`
}

// CreateIntermediateCARequest is POST /pki/intermediate.
type CreateIntermediateCARequest struct {
	ParentName string `json:"parent_name" binding:"required"`
	Name       string `json:"name" binding:"required"`
	CommonName string `json:"common_name" binding:"required"`
	TTL        string `json:"ttl" binding:"required"`
	KeyBits    int    `json:"key_bits"`
}

// IssueClientCertRequest is POST /pki/issue-client-cert (W34-02).
type IssueClientCertRequest struct {
	Role       string `json:"role" binding:"required"`
	CommonName string `json:"common_name" binding:"required"`
	TTL        string `json:"ttl"`
}

// IssueClientCertResponse returns a client certificate for API mTLS.
type IssueClientCertResponse struct {
	CertPEM       string `json:"cert_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
	Serial        string `json:"serial"`
	ExpiresAt     string `json:"expires_at"`
}

// IssueCertRequest is POST /pki/issue.
type IssueCertRequest struct {
	Role        string   `json:"role" binding:"required"`
	CommonName  string   `json:"common_name" binding:"required"`
	DNSNames    []string `json:"dns_names"`
	IPAddresses []string `json:"ip_addresses"`
	TTL         string   `json:"ttl"`
	KeyBits     int      `json:"key_bits"`
	AutoRenew   bool     `json:"auto_renew"`
}

// RenewCertRequest is POST /pki/renew.
type RenewCertRequest struct {
	CAID   string `json:"ca_id" binding:"required"`
	Serial string `json:"serial" binding:"required"`
	TTL    string `json:"ttl"`
}

// RenewCertResponse is returned for certificate renewal.
type RenewCertResponse struct {
	PreviousSerial string `json:"previous_serial"`
	CertPEM        string `json:"cert_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	Serial         string `json:"serial"`
	ExpiresAt      string `json:"expires_at"`
}

// CAResponse is returned for CA operations.
type CAResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	CertPEM   string `json:"cert_pem"`
	Serial    string `json:"serial"`
	ExpiresAt string `json:"expires_at"`
}

// IssueCertResponse is returned for leaf issuance.
type IssueCertResponse struct {
	CertPEM       string `json:"cert_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
	Serial        string `json:"serial"`
	ExpiresAt     string `json:"expires_at"`
}

// RevokeCertRequest is POST /pki/revoke.
type RevokeCertRequest struct {
	CAID   string `json:"ca_id" binding:"required"`
	Serial string `json:"serial" binding:"required"`
	Reason string `json:"reason"`
}

// CRLResponse wraps a PEM CRL.
type CRLResponse struct {
	CRLPEM string `json:"crl_pem"`
}

// ImportCARequest is POST /pki/ca/import.
type ImportCARequest struct {
	Name       string `json:"name" binding:"required"`
	CommonName string `json:"common_name,omitempty"`
	CertPEM    string `json:"cert_pem" binding:"required"`
	KeyPEM     string `json:"key_pem" binding:"required"`
	ParentName string `json:"parent_name,omitempty"`
}

// ExportCAResponse is GET /pki/ca/:id/export.
type ExportCAResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CertPEM   string `json:"cert_pem"`
	ChainPEM  string `json:"chain_pem"`
	Serial    string `json:"serial"`
	ExpiresAt string `json:"expires_at"`
}
