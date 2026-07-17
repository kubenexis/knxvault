// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// SignRequest is the body cert-manager (and Vault clients) POST to /v1/<mount>/sign/<role>.
// Fields match cert-manager internal/vault Vault.Sign parameters.
type SignRequest struct {
	CSR               string `json:"csr"`
	CommonName        string `json:"common_name"`
	AltNames          string `json:"alt_names"` // comma-separated DNS SANs
	IPSANs            string `json:"ip_sans"`   // comma-separated IPs
	URISANs           string `json:"uri_sans"`  // comma-separated URIs
	TTL               string `json:"ttl"`
	ExcludeCNFromSANs string `json:"exclude_cn_from_sans"` // "true" / "false"
	Format            string `json:"format"`
}

// SplitCSV splits a Vault-style comma-separated list, trimming empties.
func SplitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// DNSNames returns alt_names as a slice.
func (r SignRequest) DNSNames() []string {
	return SplitCSV(r.AltNames)
}

// IPAddresses returns ip_sans as a slice.
func (r SignRequest) IPAddresses() []string {
	return SplitCSV(r.IPSANs)
}

// URIs returns uri_sans as a slice.
func (r SignRequest) URIs() []string {
	return SplitCSV(r.URISANs)
}

// SignResult is the façade output from native PKI, ready for Vault mapping.
type SignResult struct {
	Certificate string
	IssuingCA   string
	CAChain     []string
	Serial      string
	// Expiration is unix seconds when known; 0 omits a zero value preference.
	Expiration int64
	PrivateKey string // optional; cert-manager CSR path leaves empty
}

// SecretResponse is a Vault Logical secret response for PKI sign/issue.
// cert-manager decodes this into certutil.Secret and ParsePKIMap(data).
type SecretResponse struct {
	RequestID     string         `json:"request_id"`
	LeaseID       string         `json:"lease_id"`
	Renewable     bool           `json:"renewable"`
	LeaseDuration int            `json:"lease_duration"`
	Data          map[string]any `json:"data"`
	Warnings      any            `json:"warnings"`
	Auth          any            `json:"auth"`
}

// NewSignSecretResponse builds a Vault PKI sign response from SignResult.
func NewSignSecretResponse(r SignResult) SecretResponse {
	chain := r.CAChain
	if chain == nil {
		chain = []string{}
	}
	// certutil expects ca_chain as a list of PEM strings.
	caChainAny := make([]any, len(chain))
	for i, pem := range chain {
		caChainAny[i] = pem
	}
	issuing := r.IssuingCA
	if issuing == "" && len(chain) > 0 {
		// Vault "issuing_ca" is the immediate issuer (last in chain when chain is root→…→issuer).
		issuing = chain[len(chain)-1]
	}
	data := map[string]any{
		"certificate":   r.Certificate,
		"issuing_ca":    issuing,
		"ca_chain":      caChainAny,
		"serial_number": r.Serial,
	}
	if r.Expiration > 0 {
		data["expiration"] = r.Expiration
	}
	if r.PrivateKey != "" {
		data["private_key"] = r.PrivateKey
		data["private_key_type"] = "rsa"
	}
	return SecretResponse{
		RequestID:     uuid.NewString(),
		LeaseID:       "",
		Renewable:     false,
		LeaseDuration: 0,
		Data:          data,
		Warnings:      nil,
		Auth:          nil,
	}
}

// ExpirationUnix returns unix seconds for t, or 0 if zero time.
func ExpirationUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// ParseSignPath extracts mount and role from a path like "pki/sign/web-server"
// or "/v1/pki_int/sign/role-name". Returns empty strings if not a sign path.
func ParseSignPath(p string) (mount, role string) {
	p = strings.Trim(p, "/")
	p = strings.TrimPrefix(p, "v1/")
	parts := strings.Split(p, "/")
	// expect: <mount>/sign/<role>
	if len(parts) < 3 {
		return "", ""
	}
	// find "sign" segment
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "sign" && i > 0 {
			mount = strings.Join(parts[:i], "/")
			role = strings.Join(parts[i+1:], "/")
			return mount, role
		}
	}
	return "", ""
}
