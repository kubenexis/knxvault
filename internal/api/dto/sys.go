package dto

// CapabilitiesResponse is GET /sys/capabilities.
type CapabilitiesResponse struct {
	Capabilities []string `json:"capabilities"`
}

// InitRequest is POST /sys/init.
type InitRequest struct {
	CreateRootCA   bool   `json:"create_root_ca"`
	RootCAName     string `json:"root_ca_name,omitempty"`
	RootCommonName string `json:"root_common_name,omitempty"`
}

// RotateMasterKeyRequest is POST /sys/rotate-master-key.
type RotateMasterKeyRequest struct {
	NewKey string `json:"new_key"`
}

// RotateMasterKeyResponse is returned after master key rotation.
type RotateMasterKeyResponse struct {
	KeyVersion int `json:"key_version"`
}

// UnsealRequest is POST /sys/unseal.
type UnsealRequest struct {
	Key     string `json:"key"`
	ShareID int    `json:"share_id,omitempty"`
}

// UnsealResponse is returned by POST /sys/unseal.
type UnsealResponse struct {
	Sealed    bool `json:"sealed"`
	Progress  int  `json:"progress,omitempty"`
	Threshold int  `json:"threshold,omitempty"`
}

// IssueListenerTLSRequest is POST /sys/tls/issue-listener.
type IssueListenerTLSRequest struct {
	Role       string   `json:"role,omitempty"`
	CommonName string   `json:"common_name,omitempty"`
	DNSNames   []string `json:"dns_names,omitempty"`
	TTL        string   `json:"ttl,omitempty"`
}

// IssueListenerTLSResponse is returned by POST /sys/tls/issue-listener.
type IssueListenerTLSResponse struct {
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	Serial    string `json:"serial"`
	ExpiresAt string `json:"expires_at"`
}

// RaftAddNodeRequest is POST /sys/raft/add-node.
type RaftAddNodeRequest struct {
	NodeID  uint64 `json:"node_id"`
	Address string `json:"address"`
}

// RaftRemoveNodeRequest is POST /sys/raft/remove-node.
type RaftRemoveNodeRequest struct {
	NodeID uint64 `json:"node_id"`
}
