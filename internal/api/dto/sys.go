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
// Provide either Key (full unseal key, base64) or Share (Shamir share, base64).
type UnsealRequest struct {
	Key   string `json:"key,omitempty"`
	Share string `json:"share,omitempty"`
}

// UnsealResponse is returned after unseal attempts (including multi-share progress).
type UnsealResponse struct {
	Sealed   bool `json:"sealed"`
	Progress int  `json:"progress,omitempty"`
	Threshold int `json:"threshold,omitempty"`
}

// SplitUnsealRequest is POST /sys/generate-unseal-shares (admin).
// Key is the full unseal key (base64); operator splits offline-capable and stores shares securely.
type SplitUnsealRequest struct {
	Key       string `json:"key"`
	Shares    int    `json:"shares"`    // n
	Threshold int    `json:"threshold"` // t
}

// SplitUnsealResponse returns base64 Shamir shares (operator must store offline).
type SplitUnsealResponse struct {
	Shares    []string `json:"shares"`
	Threshold int      `json:"threshold"`
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

// IssueListenerTLSRequest is POST /sys/tls/issue-listener.
type IssueListenerTLSRequest struct {
	Role       string   `json:"role" binding:"required"`
	CommonName string   `json:"common_name" binding:"required"`
	DNSNames   []string `json:"dns_names,omitempty"`
	CertFile   string   `json:"cert_file,omitempty"`
	KeyFile    string   `json:"key_file,omitempty"`
	TTL        string   `json:"ttl,omitempty"`
}

// IssueListenerTLSResponse is returned after listener TLS issuance.
type IssueListenerTLSResponse struct {
	CertPEM       string `json:"cert_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
	Serial        string `json:"serial"`
	ExpiresAt     string `json:"expires_at"`
	CertFile      string `json:"cert_file,omitempty"`
	KeyFile       string `json:"key_file,omitempty"`
}

// RotationRunRequest is POST /sys/rotation/run.
type RotationRunRequest struct {
	DBGrace  string `json:"db_grace,omitempty"`
	SSHGrace string `json:"ssh_grace,omitempty"`
	PKIGrace string `json:"pki_grace,omitempty"`
}
